define({
  api: [
    {
      type: "get",
      url: "/accounts",
      title: "Retrieve list of accounts",
      name: "accounts",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of accounts</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "accounts" : [\n    { "user": \'Adam\', "account_id": \'123\', balance: 500 ... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/deposits",
      title: "Retrieve summary of deposits",
      name: "deposits",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of deposits</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "deposits" : [\n    { "seller": \'Adam\', "buyer": \'bob\' ... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/users",
      title: "Retrieve user list",
      name: "getUsers",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              type: "Object",
              optional: false,
              field: "users",
              description: "<p>List of users</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "users" : [\n    { "username": \'John Doe\', "email": \'johndoe@gmail.com\', ...},\n    { "username": \'Jane Doe\', "email": \'janedoe@gmail.com\', ...}\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/invoices",
      title: "Retrieve summary of invoices",
      name: "invoices",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of invoices</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "invoices" : [\n    { "seller": \'Adam\', "buyer": \'bob\' ... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/orders",
      title: "Retrieve summary of orders",
      name: "orders",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of orders</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "orders" : [\n    { "seller": \'Adam\', "buyer": \'bob\' ... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/payments",
      title: "Retrieve summary of payments",
      name: "payments",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of payments</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "payments" : [\n    { "seller": \'Adam\', "buyer": \'bob\' ... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/referrals",
      title: "Retrieve list of referral tokens",
      name: "referrals",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of referral tokens</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              "HTTP/1.1 200 OK\n{\n  \"referrals\" : [\n    { \"token\": '***', \"status\": 'pending', sponsor: 'Adam', user: 'newUsername1', expiry: null },\n    { \"token\": '***', \"status\": 'pending', sponsor: 'Adam', user: 'newUsername2', expiry: null },\n   ]\n}",
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/referrals",
      title: "Retrieve list of referral tokens",
      name: "referrals",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of referral tokens</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              "HTTP/1.1 200 OK\n{\n  \"referrals\" : [\n    { \"token\": '***', \"status\": 'pending', sponsor: 'Adam', user: 'newUsername1', expiry: null },\n    { \"token\": '***', \"status\": 'pending', sponsor: 'Adam', user: 'newUsername2', expiry: null },\n   ]\n}",
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/user_kyc",
      title: "Retrieve user kyc details",
      name: "user_kyc",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of kyc details for each user</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "users" : [\n    { "username": \'Adam\', "email": \'adam@gmail.com\', ... kyc_data... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/transactions",
      title: "Retrieve summary of user transactions",
      name: "user_transactions",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of invoices, payments, orders for users</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "transactions" : [\n    { "username": \'Adam\', "email": \'adam@gmail.com\', invoices: 1, orders: 0, payments: 2 },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/withdrawals",
      title: "Retrieve summary of withdrawals",
      name: "withdrawals",
      group: "Admin",
      permission: [
        {
          name: "admin"
        }
      ],
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "returns",
              description: "<p>list of withdrawals</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "withdrawals" : [\n    { "seller": \'Adam\', "buyer": \'bob\' ... },\n     ...\n   ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/admin.js",
      groupTitle: "Admin"
    },
    {
      type: "get",
      url: "/info",
      title: "Request server information",
      name: "GetInfo",
      group: "Info",
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              type: "Object",
              optional: false,
              field: "fx",
              description:
                "<p>Exchange rates relative to USD - fx.CUR is the value of one CUR in USD.</p>"
            },
            {
              group: "Success 200",
              type: "String[]",
              optional: false,
              field: "networks",
              description:
                "<p>Array of supported networks; possible values are &quot;bitcoin&quot;, &quot;liquid&quot; and &quot;lightning&quot;.</p>"
            },
            {
              group: "Success 200",
              type: "String",
              optional: false,
              field: "clientVersion",
              description: "<p>the current git commit of the ui</p>"
            }
          ]
        }
      },
      version: "0.0.0",
      filename: "routes/info.js",
      groupTitle: "Info"
    },
    {
      type: "post",
      url: "/grant",
      title: "Grant Referral code",
      name: "Grant",
      group: "Referrals",
      permission: [
        {
          name: "member"
        }
      ],
      parameter: {
        fields: {
          Parameter: [
            {
              group: "Parameter",
              type: "sponsor_id",
              optional: false,
              field: "user_id",
              description: "<p>of member generating referral code.</p>"
            },
            {
              group: "Parameter",
              type: "expiry",
              optional: false,
              field: "optional",
              description: "<p>expiry date for token.</p>"
            }
          ]
        }
      },
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              type: "String",
              optional: false,
              field: "token",
              description: "<p>referral token</p>"
            },
            {
              group: "Success 200",
              type: "Date",
              optional: false,
              field: "expiry",
              description: "<p>optional expiry</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n   "token": "*********", \n   "status": "available", \n   "expiry": null\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/referrals.js",
      groupTitle: "Referrals"
    },
    {
      type: "get",
      url: "/grant",
      title: "Grant Referral code (variation using get)",
      name: "Grant",
      group: "Referrals",
      permission: [
        {
          name: "member"
        },
        {
          name: "member"
        }
      ],
      parameter: {
        fields: {
          Parameter: [
            {
              group: "Parameter",
              type: "sponsor_id",
              optional: false,
              field: "user_id",
              description: "<p>of member generating referral code.</p>"
            },
            {
              group: "Parameter",
              type: "expiry",
              optional: false,
              field: "optional",
              description: "<p>expiry date for token.</p>"
            }
          ]
        }
      },
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              type: "String",
              optional: false,
              field: "token",
              description: "<p>referral token</p>"
            },
            {
              group: "Success 200",
              type: "Status",
              optional: false,
              field: "status",
              description: "<p>referral status</p>"
            },
            {
              group: "Success 200",
              type: "Date",
              optional: false,
              field: "expiry",
              description: "<p>optional expiry</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n   "token": "*********", \n   "status": "available", \n   "expiry": null\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/referrals.js",
      groupTitle: "Referrals"
    },
    {
      type: "get",
      url: "/checkTokens/:sponsor_id",
      title: "Retrieve list of referral tokens generated by this user",
      name: "checkTokens",
      group: "Referrals",
      permission: [
        {
          name: "member"
        }
      ],
      parameter: {
        fields: {
          Parameter: [
            {
              group: "Parameter",
              type: "sponsor_id",
              optional: false,
              field: "user_id",
              description: "<p>of member generating referral code.</p>"
            },
            {
              group: "Parameter",
              type: "status",
              optional: false,
              field: "optional",
              description: "<p>token status.</p>"
            }
          ]
        }
      },
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "tokens",
              description: "<p>array of token objects</p>"
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "tokens": [\n    {"token": "*********", "status": "available", "expiry": null}\n  ]\n}',
            type: "json"
          }
        ]
      },
      version: "0.0.0",
      filename: "routes/referrals.js",
      groupTitle: "Referrals"
    },
    {
      type: "get",
      url: "/isReferred/:user_id",
      title: "Check if user is referred",
      name: "isReferred",
      group: "Referrals",
      parameter: {
        fields: {
          Parameter: [
            {
              group: "Parameter",
              type: "user_id",
              optional: false,
              field: "user",
              description: "<p>id</p>"
            }
          ]
        }
      },
      success: {
        examples: [
          {
            title: "Success-Response:",
            content: "HTTP/1.1 200 OK\n{\n  true\n}",
            type: "json"
          }
        ]
      },
      description:
        "<p>returns boolean indicating if user is referred or not</p>",
      version: "0.0.0",
      filename: "routes/referrals.js",
      groupTitle: "Referrals"
    },
    {
      type: "post",
      url: "/joinQueue",
      title: "Join waiting list (track email & phone)",
      name: "joinQueue",
      group: "Referrals",
      parameter: {
        fields: {
          Parameter: [
            {
              group: "Parameter",
              type: "email",
              optional: false,
              field: "email",
              description: "<p>address</p>"
            },
            {
              group: "Parameter",
              type: "phone",
              optional: false,
              field: "phone",
              description: "<p>number</p>"
            }
          ]
        }
      },
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "verified",
              defaultValue: "true",
              description: ""
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content:
              'HTTP/1.1 200 OK\n{\n  "success": true\n  "message": \'Added to waiting list\'\n}',
            type: "json"
          }
        ]
      },
      description: "<p>referral token is updated with existing user_id</p>",
      version: "0.0.0",
      filename: "routes/referrals.js",
      groupTitle: "Referrals"
    },
    {
      type: "get",
      url: "/verify/:user_id",
      title: "Verify token and apply to existing user",
      name: "verify",
      group: "Referrals",
      permission: [
        {
          name: "member"
        }
      ],
      parameter: {
        fields: {
          Parameter: [
            {
              group: "Parameter",
              type: "user_id",
              optional: false,
              field: "Current",
              description: "<p>user</p>"
            },
            {
              group: "Parameter",
              type: "token",
              optional: false,
              field: "Token",
              description: "<p>to validate</p>"
            }
          ]
        }
      },
      success: {
        fields: {
          "Success 200": [
            {
              group: "Success 200",
              optional: false,
              field: "verified",
              defaultValue: "true",
              description: ""
            }
          ]
        },
        examples: [
          {
            title: "Success-Response:",
            content: 'HTTP/1.1 200 OK\n{\n  "verified": true\n}',
            type: "json"
          }
        ]
      },
      description: "<p>referral token is updated with existing user_id</p>",
      version: "0.0.0",
      filename: "routes/referrals.js",
      groupTitle: "Referrals"
    }
  ]
});
