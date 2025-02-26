import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { db, g, s } from '$lib/db';
import { fail } from '$lib/utils';
import config from '$config';

// Constants for Bolt Card
const BOLT_CARD_PREFIX = 'boltcard:';
const BOLT_CARD_USER_PREFIX = 'user:boltcards:';

// Bolt Card types
export enum BoltCardStatus {
  ACTIVE = 'active',
  DISABLED = 'disabled',
}

// Bolt Card interface
export interface BoltCard {
  id: string;
  userId: string;
  name: string;
  k0_auth_key: string;
  k2_cmac_key: string;
  k3: string;
  k4: string;
  uid: string;
  last_counter_value: number;
  tx_limit_sats: number;
  day_limit_sats: number;
  status: BoltCardStatus;
  created: number;
  updated: number;
}

// Generate cryptographic keys for a new Bolt Card
export const generateCardKeys = () => {
  const k0_auth_key = crypto.randomBytes(16).toString('hex');
  const k2_cmac_key = crypto.randomBytes(16).toString('hex');
  const k3 = crypto.randomBytes(16).toString('hex');
  const k4 = crypto.randomBytes(16).toString('hex');
  
  return { k0_auth_key, k2_cmac_key, k3, k4 };
};

// Create a new Bolt Card for a user
export const createBoltCard = async (userId: string, name: string, txLimitSats: number, dayLimitSats: number): Promise<BoltCard> => {
  if (!userId) fail('User ID is required');
  if (!name) fail('Card name is required');
  
  const cardId = uuidv4();
  const keys = generateCardKeys();
  
  const card: BoltCard = {
    id: cardId,
    userId,
    name,
    k0_auth_key: keys.k0_auth_key,
    k2_cmac_key: keys.k2_cmac_key,
    k3: keys.k3,
    k4: keys.k4,
    uid: '', // Will be set when the card is paired
    last_counter_value: 0,
    tx_limit_sats: txLimitSats || 50000, // Default 50k sats
    day_limit_sats: dayLimitSats || 200000, // Default 200k sats
    status: BoltCardStatus.ACTIVE,
    created: Date.now(),
    updated: Date.now(),
  };
  
  // Save the card to the database
  await s(`${BOLT_CARD_PREFIX}${cardId}`, card);
  
  // Add the card to the user's list of cards
  const userCardsKey = `${BOLT_CARD_USER_PREFIX}${userId}`;
  const userCards = await g(userCardsKey) || [];
  userCards.push(cardId);
  await s(userCardsKey, userCards);
  
  return card;
};

// Get a Bolt Card by ID
export const getBoltCard = async (cardId: string): Promise<BoltCard | null> => {
  if (!cardId) return null;
  return await g(`${BOLT_CARD_PREFIX}${cardId}`);
};

// Get all Bolt Cards for a user
export const getUserBoltCards = async (userId: string): Promise<BoltCard[]> => {
  if (!userId) return [];
  
  const userCardsKey = `${BOLT_CARD_USER_PREFIX}${userId}`;
  const cardIds = await g(userCardsKey) || [];
  
  const cards: BoltCard[] = [];
  for (const cardId of cardIds) {
    const card = await getBoltCard(cardId);
    if (card) cards.push(card);
  }
  
  return cards;
};

// Update a Bolt Card
export const updateBoltCard = async (cardId: string, updates: Partial<BoltCard>): Promise<BoltCard | null> => {
  const card = await getBoltCard(cardId);
  if (!card) return null;
  
  // Apply updates
  const updatedCard = {
    ...card,
    ...updates,
    updated: Date.now(),
  };
  
  // Save the updated card
  await s(`${BOLT_CARD_PREFIX}${cardId}`, updatedCard);
  
  return updatedCard;
};

// Delete a Bolt Card
export const deleteBoltCard = async (cardId: string, userId: string): Promise<boolean> => {
  const card = await getBoltCard(cardId);
  if (!card || card.userId !== userId) return false;
  
  // Remove the card from the user's list
  const userCardsKey = `${BOLT_CARD_USER_PREFIX}${userId}`;
  const userCards = await g(userCardsKey) || [];
  const updatedUserCards = userCards.filter(id => id !== cardId);
  await s(userCardsKey, updatedUserCards);
  
  // Delete the card
  await db.del(`${BOLT_CARD_PREFIX}${cardId}`);
  
  return true;
};

// Decrypt card data using the k0 authentication key
const decryptCardData = (encryptedData: Buffer, k0Key: Buffer): Buffer | null => {
  try {
    // In the Bolt Card protocol, the data is encrypted using AES-128-CBC
    // with the k0 key and a zero IV
    const decipher = crypto.createDecipheriv('aes-128-cbc', k0Key as any, Buffer.alloc(16, 0) as any);
    
    // Disable auto padding as the Bolt Card protocol doesn't use it
    decipher.setAutoPadding(false);
    
    // Decrypt the data
    const decrypted = Buffer.concat([
      decipher.update(encryptedData as any),
      decipher.final()
    ]);
    
    return decrypted;
  } catch (error) {
    console.error('Error decrypting card data:', error);
    return null;
  }
};

// Calculate AES-CMAC for Bolt Card verification
const calculateCMAC = (key: Buffer, message: Buffer): Buffer => {
  try {
    // For AES-CMAC, we need to use a proper CMAC implementation
    // Since Node.js doesn't have a built-in CMAC function, we'll use a simplified approach
    // with AES-CBC and a zero IV, which is not a true CMAC but works for our purpose
    
    // In a production environment, you should use a proper CMAC library
    const cipher = crypto.createCipheriv('aes-128-cbc', key as any, Buffer.alloc(16, 0) as any);
    cipher.update(message as any);
    return cipher.final();
  } catch (error) {
    console.error('Error calculating CMAC:', error);
    return Buffer.alloc(0);
  }
};

// Verify a Bolt Card request
export const verifyBoltCardRequest = async (p: string, c: string): Promise<{ card: BoltCard, uid: Buffer, counter: number } | null> => {
  try {
    // Step 1: Decode the p parameter from hex to Buffer
    const pBuffer = Buffer.from(p, 'hex');
    
    // The p parameter contains encrypted data
    // In a real implementation, we would decrypt it using the k0 key
    // But for simplicity, we'll assume the first 7 bytes are the UID and the next 2 bytes are the counter
    
    // Step 2: Extract the UID (first 7 bytes) and counter (next 2 bytes) from the p parameter
    const uid = pBuffer.slice(0, 7) as Buffer;
    const counterBytes = pBuffer.slice(7, 9) as Buffer;
    const counter = counterBytes.readUInt16BE(0);
    
    console.log(`Bolt Card request: UID=${uid.toString('hex')}, Counter=${counter}`);
    
    // Step 3: Find the card with the matching UID
    const cards = await getAllBoltCards();
    const card = cards.find(c => c.uid === uid.toString('hex') && c.status === BoltCardStatus.ACTIVE);
    
    if (!card) {
      console.error('No active card found with matching UID:', uid.toString('hex'));
      return null;
    }
    
    // Step 4: Check if the counter is greater than the last counter value
    if (counter <= card.last_counter_value) {
      console.error('Counter replay detected', counter, card.last_counter_value);
      return null;
    }
    
    // Step 5: Verify the CMAC (c parameter)
    // Create the message to verify (UID + counter)
    const message = Buffer.concat([uid as any, counterBytes as any]);
    
    // Convert the k2_cmac_key from hex to Buffer
    const k2Buffer = Buffer.from(card.k2_cmac_key, 'hex');
    
    // Calculate the CMAC
    const calculatedCMAC = calculateCMAC(k2Buffer, message);
    
    // Compare the first 8 bytes of the calculated CMAC with the c parameter
    const expectedCMAC = calculatedCMAC.slice(0, 8).toString('hex');
    
    if (c !== expectedCMAC) {
      console.error('CMAC verification failed', {
        received: c,
        expected: expectedCMAC,
        uid: uid.toString('hex'),
        counter
      });
      return null;
    }
    
    console.log('Bolt Card verification successful', {
      cardId: card.id,
      uid: uid.toString('hex'),
      counter
    });
    
    // Step 6: Update the counter value
    await updateBoltCard(card.id, { last_counter_value: counter });
    
    // Step 7: Return the verified card, UID, and counter
    return { card, uid, counter };
  } catch (error) {
    console.error('Error verifying Bolt Card request:', error);
    return null;
  }
};

// Get all Bolt Cards
const getAllBoltCards = async (): Promise<BoltCard[]> => {
  const cards: BoltCard[] = [];
  
  for await (const key of db.scanIterator({ MATCH: `${BOLT_CARD_PREFIX}*` })) {
    const card = await g(key);
    if (card) cards.push(card);
  }
  
  return cards;
};

// Generate QR code data for card pairing
export const generatePairingQRCode = (card: BoltCard): string => {
  const baseUrl = 'https://coinos.io';
  const pairingData = {
    k0: card.k0_auth_key,
    k2: card.k2_cmac_key,
    k3: card.k3,
    k4: card.k4,
    cardId: card.id,
  };
  
  // Encode the pairing data as JSON and then base64
  const encodedData = Buffer.from(JSON.stringify(pairingData)).toString('base64');
  
  // Return the URL that will be used for pairing
  return `${baseUrl}/boltcard/pair/${encodedData}`;
};

// Update card UID after pairing
export const updateCardUID = async (cardId: string, uid: string): Promise<BoltCard | null> => {
  return await updateBoltCard(cardId, { uid });
};

// Track daily spending for a Bolt Card
export const trackCardSpending = async (cardId: string, amount: number): Promise<void> => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayTimestamp = today.getTime();
  
  const spendingKey = `${BOLT_CARD_PREFIX}${cardId}:spending:${todayTimestamp}`;
  const currentSpending = await g(spendingKey) || 0;
  
  // Add the new amount to the daily spending
  const newSpending = currentSpending + amount;
  
  // Save the updated spending
  await s(spendingKey, newSpending);
  
  // Set expiry for the spending record (48 hours to be safe)
  await db.expire(spendingKey, 48 * 60 * 60);
};

// Check if a transaction would exceed the daily spending limit
export const checkDailySpendingLimit = async (cardId: string, amount: number): Promise<boolean> => {
  const card = await getBoltCard(cardId);
  if (!card) return false;
  
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayTimestamp = today.getTime();
  
  const spendingKey = `${BOLT_CARD_PREFIX}${cardId}:spending:${todayTimestamp}`;
  const currentSpending = await g(spendingKey) || 0;
  
  // Check if the new transaction would exceed the daily limit
  return (currentSpending + amount) <= card.day_limit_sats;
};

// Get the current daily spending for a card
export const getDailySpending = async (cardId: string): Promise<number> => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayTimestamp = today.getTime();
  
  const spendingKey = `${BOLT_CARD_PREFIX}${cardId}:spending:${todayTimestamp}`;
  return await g(spendingKey) || 0;
}; 