import { FastifyRequest, FastifyReply } from 'fastify';
import * as crypto from 'crypto';
import { 
  BoltCard, 
  BoltCardStatus, 
  createBoltCard, 
  deleteBoltCard, 
  getBoltCard, 
  generatePairingQRCode, 
  generatePairingJSON,
  getUserBoltCards, 
  updateBoltCard, 
  updateCardUID, 
  verifyBoltCardRequest,
  trackCardSpending,
  checkDailySpendingLimit,
  getDailySpending
} from '$lib/boltcard';
import { db, g, s } from '$lib/db';
import { err, l } from '$lib/logging';
import { fail, getUser } from '$lib/utils';
import { sendLightning } from '$lib/payments';
import config from '$config';

// Define custom request type with user property
interface RequestWithUser extends FastifyRequest {
  user?: any;
}

// Interface for LNURLW response
interface LnurlwResponse {
  tag: string;
  callback: string;
  k1: string;
  minWithdrawable: number;
  maxWithdrawable: number;
  defaultDescription: string;
  balanceCheck: string;
  payLink: string;
  cardName: string;
  cardId: string;
  [key: string]: any;
}

// Interface for LNURLW callback request
interface LnurlwCallbackRequest {
  k1: string;
  pr: string;
}

// Create a new Bolt Card
export async function createCard(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    const { name, txLimitSats, dayLimitSats } = req.body as any;
    
    if (!user) fail('User not authenticated');
    if (!name) fail('Card name is required');
    
    const card = await createBoltCard(
      user.id, 
      name, 
      parseInt(txLimitSats) || 50000, 
      parseInt(dayLimitSats) || 200000
    );
    
    // Generate the programming URL
    const programmingUrl = generatePairingQRCode(card);
    
    res.send({ 
      card,
      programmingUrl
    });
  } catch (e) {
    err('Error creating Bolt Card', e);
    res.code(500).send({ error: e.message });
  }
}

// Get all Bolt Cards for a user
export async function getCards(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    
    if (!user) fail('User not authenticated');
    
    const cards = await getUserBoltCards(user.id);
    
    res.send({ cards });
  } catch (e) {
    err('Error getting Bolt Cards', e);
    res.code(500).send({ error: e.message });
  }
}

// Get a specific Bolt Card
export async function getCard(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    const { id } = req.params as any;
    
    if (!user) fail('User not authenticated');
    if (!id) fail('Card ID is required');
    
    const card = await getBoltCard(id);
    
    if (!card) {
      return res.code(404).send({ error: 'Card not found' });
    }
    
    if (card.userId !== user.id) {
      return res.code(403).send({ error: 'Not authorized to access this card' });
    }
    
    // Generate programming URL if the card is not paired yet
    let programmingUrl = null;
    
    if (!card.uid) {
      programmingUrl = generatePairingQRCode(card);
    }
    
    res.send({ 
      card,
      programmingUrl
    });
  } catch (e) {
    err('Error getting Bolt Card', e);
    res.code(500).send({ error: e.message });
  }
}

// Update a Bolt Card
export async function updateCard(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    const { id } = req.params as any;
    const updates = req.body as any;
    
    if (!user) fail('User not authenticated');
    if (!id) fail('Card ID is required');
    
    const card = await getBoltCard(id);
    
    if (!card) {
      return res.code(404).send({ error: 'Card not found' });
    }
    
    if (card.userId !== user.id) {
      return res.code(403).send({ error: 'Not authorized to update this card' });
    }
    
    // Only allow updating certain fields
    const allowedUpdates = {
      name: updates.name,
      tx_limit_sats: parseInt(updates.txLimitSats) || card.tx_limit_sats,
      day_limit_sats: parseInt(updates.dayLimitSats) || card.day_limit_sats,
      status: updates.status || card.status,
    };
    
    const updatedCard = await updateBoltCard(id, allowedUpdates);
    
    res.send({ card: updatedCard });
  } catch (e) {
    err('Error updating Bolt Card', e);
    res.code(500).send({ error: e.message });
  }
}

// Delete a Bolt Card
export async function deleteCard(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    const { id } = req.params as any;
    
    if (!user) fail('User not authenticated');
    if (!id) fail('Card ID is required');
    
    const card = await getBoltCard(id);
    
    if (!card) {
      return res.code(404).send({ error: 'Card not found' });
    }
    
    if (card.userId !== user.id) {
      return res.code(403).send({ error: 'Not authorized to delete this card' });
    }
    
    const deleted = await deleteBoltCard(id, user.id);
    
    if (!deleted) {
      return res.code(500).send({ error: 'Failed to delete card' });
    }
    
    res.send({ success: true });
  } catch (e) {
    err('Error deleting Bolt Card', e);
    res.code(500).send({ error: e.message });
  }
}

// Pair a Bolt Card with a UID
export async function pairCard(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    const { id, uid } = req.body as any;
    
    if (!user) fail('User not authenticated');
    if (!id) fail('Card ID is required');
    if (!uid) fail('UID is required');
    
    // Validate UID format (should be a 7-byte hex string)
    if (!/^[0-9a-fA-F]{14}$/.test(uid)) {
      return res.code(400).send({ error: 'Invalid UID format. Expected 7-byte hex string (14 characters)' });
    }
    
    const card = await getBoltCard(id);
    
    if (!card) {
      return res.code(404).send({ error: 'Card not found' });
    }
    
    if (card.userId !== user.id) {
      return res.code(403).send({ error: 'Not authorized to pair this card' });
    }
    
    // Check if the card is already paired
    if (card.uid) {
      return res.code(400).send({ error: 'Card is already paired' });
    }
    
    // Update the card with the UID
    const updatedCard = await updateCardUID(id, uid);
    
    if (!updatedCard) {
      return res.code(500).send({ error: 'Failed to update card' });
    }
    
    l('Card paired successfully', { cardId: id, uid });
    
    res.send({ 
      success: true,
      card: updatedCard
    });
  } catch (e) {
    err('Error pairing Bolt Card', e);
    res.code(500).send({ error: e.message });
  }
}

// Get card programming data
export async function getCardProgrammingData(req: RequestWithUser, res: FastifyReply) {
  try {
    const { user } = req;
    const { id } = req.params as any;
    
    if (!user) fail('User not authenticated');
    if (!id) fail('Card ID is required');
    
    const card = await getBoltCard(id);
    
    if (!card) {
      return res.code(404).send({ error: 'Card not found' });
    }
    
    if (card.userId !== user.id) {
      return res.code(403).send({ error: 'Not authorized to access this card' });
    }
    
    // Generate programming data in JSON format
    const programmingData = generatePairingJSON(card);
    
    res.send({ 
      success: true,
      card,
      programmingData
    });
  } catch (e) {
    err('Error getting card programming data', e);
    res.code(500).send({ error: e.message });
  }
}

// Public endpoint for NFC apps to fetch card programming data
export async function getPublicCardProgrammingData(req: FastifyRequest, res: FastifyReply) {
  try {
    const { token } = req.params as any;
    
    if (!token) {
      return res.code(400).send({ error: 'Token is required' });
    }
    
    // Decode the token (base64)
    let decodedData;
    try {
      const decoded = Buffer.from(token, 'base64').toString();
      decodedData = JSON.parse(decoded);
    } catch (e) {
      return res.code(400).send({ error: 'Invalid token format' });
    }
    
    // Extract the card ID from the decoded data
    const { cardId } = decodedData;
    
    if (!cardId) {
      return res.code(400).send({ error: 'Card ID not found in token' });
    }
    
    // Get the card
    const card = await getBoltCard(cardId);
    
    if (!card) {
      return res.code(404).send({ error: 'Card not found' });
    }
    
    // Check if the card is already paired (has a UID)
    if (card.uid) {
      return res.code(400).send({ error: 'Card is already paired' });
    }
    
    // Get the user associated with the card
    const user = await getUser({ id: card.userId });
    
    if (!user) {
      return res.code(404).send({ error: 'User not found' });
    }
    
    // Return the programming data in the format expected by NFC apps
    const baseUrl = 'https://coinos.io';
    const programmingData = {
      k0: card.k0_auth_key,
      k2: card.k2_cmac_key,
      k3: card.k3,
      k4: card.k4,
      name: card.name,
      tx_limit_sats: card.tx_limit_sats,
      day_limit_sats: card.day_limit_sats,
      lnurlw_base_url: `${baseUrl}/boltcard/lnurlw`,
      card_id: card.id,
      user_id: card.userId,
      user_name: user.username,
      callback_url: `${baseUrl}/boltcard/pair`,
      created_time: card.created
    };
    
    l('Card programming data requested', { cardId: card.id });
    
    res.send(programmingData);
  } catch (e) {
    err('Error getting public card programming data', e);
    res.code(500).send({ error: e.message });
  }
}

// LNURLW request handler
export async function lnurlwRequest(req: FastifyRequest, res: FastifyReply) {
  try {
    const { p, c } = req.query as any;
    
    if (!p || !c) {
      l('LNURLW request missing parameters', { p, c });
      return res.code(400).send({ status: 'ERROR', reason: 'Missing parameters' });
    }
    
    l('Processing LNURLW request', { p, c });
    
    // Verify the Bolt Card request
    const verification = await verifyBoltCardRequest(p, c);
    
    if (!verification) {
      l('LNURLW request verification failed');
      return res.code(400).send({ status: 'ERROR', reason: 'Invalid card' });
    }
    
    const { card, uid, counter } = verification;
    
    l('LNURLW request verification successful', { 
      cardId: card.id, 
      uid: uid.toString('hex'), 
      counter 
    });
    
    // Check if the card is active
    if (card.status !== BoltCardStatus.ACTIVE) {
      l('LNURLW request for disabled card', { cardId: card.id });
      return res.code(400).send({ status: 'ERROR', reason: 'Card is disabled' });
    }
    
    // Generate a unique k1 for this request
    const k1 = crypto.randomBytes(32).toString('hex');
    
    // Store the request details for the callback
    const requestKey = `boltcard:request:${k1}`;
    await s(requestKey, {
      cardId: card.id,
      uid: uid.toString('hex'),
      counter,
      timestamp: Date.now(),
      // Set expiry for this request (5 minutes)
      expiry: Date.now() + 5 * 60 * 1000
    });
    
    // Get the user associated with the card
    const user = await getUser({ id: card.userId });
    
    if (!user) {
      l('LNURLW request for card with invalid user', { cardId: card.id, userId: card.userId });
      return res.code(400).send({ status: 'ERROR', reason: 'Invalid user' });
    }
    
    // Construct the LNURLW response
    const baseUrl = 'https://coinos.io';
    const response: LnurlwResponse = {
      tag: 'withdrawRequest',
      callback: `${baseUrl}/boltcard/lnurlw/callback`,
      k1,
      minWithdrawable: 1000, // 1 sat minimum
      maxWithdrawable: card.tx_limit_sats * 1000, // Convert to millisats
      defaultDescription: `Bolt Card payment for ${user.username}`,
      // Add additional fields as per the LNURL-W spec
      balanceCheck: `${baseUrl}/boltcard/balance/${card.id}`,
      payLink: `${baseUrl}/pay/${user.username}`,
      // Add card-specific metadata
      cardName: card.name,
      cardId: card.id
    };
    
    l('LNURLW response', response);
    
    res.send(response);
  } catch (e) {
    err('Error processing LNURLW request', e);
    res.code(500).send({ status: 'ERROR', reason: e.message });
  }
}

// LNURLW callback handler
export async function lnurlwCallback(req: FastifyRequest, res: FastifyReply) {
  try {
    const { k1, pr } = req.query as LnurlwCallbackRequest;
    
    if (!k1 || !pr) {
      l('LNURLW callback missing parameters', { k1, pr });
      return res.code(400).send({ status: 'ERROR', reason: 'Missing parameters' });
    }
    
    l('Processing LNURLW callback', { k1 });
    
    // Retrieve the request details
    const requestKey = `boltcard:request:${k1}`;
    const request = await g(requestKey);
    
    if (!request) {
      l('LNURLW callback with invalid k1', { k1 });
      return res.code(400).send({ status: 'ERROR', reason: 'Invalid or expired request' });
    }
    
    // Check if the request has expired
    if (request.expiry < Date.now()) {
      l('LNURLW callback with expired request', { k1, expiry: request.expiry });
      await db.del(requestKey);
      return res.code(400).send({ status: 'ERROR', reason: 'Request expired' });
    }
    
    // Get the card
    const card = await getBoltCard(request.cardId);
    
    if (!card) {
      l('LNURLW callback for non-existent card', { cardId: request.cardId });
      await db.del(requestKey);
      return res.code(400).send({ status: 'ERROR', reason: 'Card not found' });
    }
    
    // Check if the card is active
    if (card.status !== BoltCardStatus.ACTIVE) {
      l('LNURLW callback for disabled card', { cardId: card.id });
      await db.del(requestKey);
      return res.code(400).send({ status: 'ERROR', reason: 'Card is disabled' });
    }
    
    // Get the user associated with the card
    const user = await getUser({ id: card.userId });
    
    if (!user) {
      l('LNURLW callback for card with invalid user', { cardId: card.id, userId: card.userId });
      await db.del(requestKey);
      return res.code(400).send({ status: 'ERROR', reason: 'Invalid user' });
    }
    
    // Decode the payment request to check the amount
    try {
      // Decode the invoice to check the amount
      const decodedInvoice = await sendLightning({
        user,
        pr,
        amount: undefined,
        memo: `Bolt Card payment for ${card.name}`
      });
      
      // Check if the amount is within the card's limits
      const amountSats = decodedInvoice.amount_msat / 1000;
      
      if (amountSats > card.tx_limit_sats) {
        l('LNURLW callback with amount exceeding tx limit', { 
          cardId: card.id, 
          amount: amountSats, 
          limit: card.tx_limit_sats 
        });
        return res.code(400).send({ 
          status: 'ERROR', 
          reason: `Amount exceeds transaction limit of ${card.tx_limit_sats} sats` 
        });
      }
      
      // Check daily spending limit
      const currentDailySpending = await getDailySpending(card.id);
      const withinDailyLimit = await checkDailySpendingLimit(card.id, amountSats);
      
      if (!withinDailyLimit) {
        l('LNURLW callback with amount exceeding daily limit', { 
          cardId: card.id, 
          amount: amountSats, 
          currentSpending: currentDailySpending,
          dailyLimit: card.day_limit_sats 
        });
        return res.code(400).send({ 
          status: 'ERROR', 
          reason: `Amount exceeds daily limit of ${card.day_limit_sats} sats (current: ${currentDailySpending})` 
        });
      }
      
      // Pay the invoice
      l('Paying invoice for Bolt Card', { cardId: card.id, amount: amountSats });
      const payment = await sendLightning({
        user,
        pr,
        amount: undefined,
        memo: `Bolt Card payment for ${card.name}`
      });
      
      if (payment.error) {
        l('Error paying invoice for Bolt Card', { cardId: card.id, error: payment.error });
        return res.code(500).send({ status: 'ERROR', reason: payment.error });
      }
      
      // Track the spending for daily limits
      await trackCardSpending(card.id, amountSats);
      
      // Record the payment
      await s(`boltcard:payment:${card.id}:${Date.now()}`, {
        cardId: card.id,
        userId: card.userId,
        amount: amountSats,
        paymentHash: payment.payment_hash,
        timestamp: Date.now()
      });
      
      // Delete the request
      await db.del(requestKey);
      
      l('Successfully paid invoice for Bolt Card', { 
        cardId: card.id, 
        amount: amountSats,
        paymentHash: payment.payment_hash
      });
      
      // Return success
      return res.send({ status: 'OK' });
    } catch (e) {
      l('Error processing payment for Bolt Card', { cardId: card.id, error: e.message });
      return res.code(500).send({ status: 'ERROR', reason: e.message });
    }
  } catch (e) {
    err('Error processing LNURLW callback', e);
    res.code(500).send({ status: 'ERROR', reason: e.message });
  }
}

// Get Bolt Card balance and spending limits
export async function getCardBalance(req: FastifyRequest, res: FastifyReply) {
  try {
    const { id } = req.params as any;
    
    if (!id) {
      return res.code(400).send({ status: 'ERROR', reason: 'Card ID is required' });
    }
    
    // Get the card
    const card = await getBoltCard(id);
    
    if (!card) {
      return res.code(404).send({ status: 'ERROR', reason: 'Card not found' });
    }
    
    // Get the current daily spending
    const currentDailySpending = await getDailySpending(card.id);
    
    // Get the user associated with the card
    const user = await getUser({ id: card.userId });
    
    if (!user) {
      return res.code(404).send({ status: 'ERROR', reason: 'User not found' });
    }
    
    // Get the user's balance
    // This would typically come from your user account system
    const balance = user.balance || 0;
    
    // Construct the response
    const response = {
      status: 'OK',
      cardId: card.id,
      cardName: card.name,
      cardStatus: card.status,
      balance,
      txLimit: card.tx_limit_sats,
      dailyLimit: card.day_limit_sats,
      currentDailySpending,
      remainingDailyLimit: card.day_limit_sats - currentDailySpending,
      username: user.username
    };
    
    res.send(response);
  } catch (e) {
    err('Error getting card balance', e);
    res.code(500).send({ status: 'ERROR', reason: e.message });
  }
}

export default {
  createCard,
  getCards,
  getCard,
  updateCard,
  deleteCard,
  pairCard,
  getCardProgrammingData,
  getPublicCardProgrammingData,
  lnurlwRequest,
  lnurlwCallback,
  getCardBalance,
}; 