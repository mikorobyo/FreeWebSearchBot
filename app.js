/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * @author Miko Santos
 * @url http://github.com/mikorobyo
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
	bodyParser = require('body-parser'),
	config = require('config'),
	crypto = require('crypto'),
	express = require('express'),
	https = require('https'),
	request = require('request'),
	rp = require('request-promise'),
	sanitizeHtml = require('sanitize-html');


var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({
	verify: verifyRequestSignature
}));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
	process.env.MESSENGER_APP_SECRET :
	config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
	(process.env.MESSENGER_VALIDATION_TOKEN) :
	config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
	(process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
	config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
	(process.env.SERVER_URL) :
	config.get('serverURL');

const SEARCH_URL = (process.env.SEARCH_URL) ?
	(process.env.SEARCH_URL) :
	config.get('searchURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
	console.error("Missing config values");
	process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
	if (req.query['hub.mode'] === 'subscribe' &&
		req.query['hub.verify_token'] === VALIDATION_TOKEN) {
		console.log("Validating webhook");
		res.status(200).send(req.query['hub.challenge']);
	} else {
		console.error("Failed validation. Make sure the validation tokens match.");
		res.sendStatus(403);
	}
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
	var data = req.body;

	// Make sure this is a page subscription
	if (data.object == 'page') {
		// Iterate over each entry
		// There may be multiple if batched
		data.entry.forEach(function (pageEntry) {
			var pageID = pageEntry.id;
			var timeOfEvent = pageEntry.time;

			// Iterate over each messaging event
			pageEntry.messaging.forEach(function (messagingEvent) {
				if (messagingEvent.optin) {
					receivedAuthentication(messagingEvent);
				} else if (messagingEvent.message) {
					receivedMessage(messagingEvent);
				} else if (messagingEvent.delivery) {
					console.log("Webhook received: deliveryConfirmation");
				} else if (messagingEvent.postback) {
					console.log("Webhook received: postback");
				} else if (messagingEvent.read) {
					console.log("Webhook received: messageRead");
				} else if (messagingEvent.account_linking) {
					console.log("Webhook received: accountLinking");
				} else {
					console.log("Webhook received unknown messagingEvent: ", messagingEvent);
				}
			});
		});

		// Assume all went well.
		//
		// You must send back a 200, within 20 seconds, to let us know you've
		// successfully received the callback. Otherwise, the request will time out.
		res.sendStatus(200);
	}
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
	var signature = req.headers["x-hub-signature"];

	if (!signature) {
		// For testing, let's log an error. In production, you should throw an
		// error.
		console.error("Couldn't validate the signature.");
	} else {
		var elements = signature.split('=');
		var method = elements[0];
		var signatureHash = elements[1];

		var expectedHash = crypto.createHmac('sha1', APP_SECRET)
			.update(buf)
			.digest('hex');

		if (signatureHash != expectedHash) {
			throw new Error("Couldn't validate the request signature.");
		}
	}
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
async function receivedAuthentication(event) {
	var senderID = event.sender.id;
	var recipientID = event.recipient.id;
	var timeOfAuth = event.timestamp;

	// The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
	// The developer can set this to an arbitrary value to associate the
	// authentication callback with the 'Send to Messenger' click event. This is
	// a way to do account linking when the user clicks the 'Send to Messenger'
	// plugin.
	var passThroughParam = event.optin.ref;

	console.log("Received authentication for user %d and page %d with pass " +
		"through param '%s' at %d", senderID, recipientID, passThroughParam,
		timeOfAuth);

	// When an authentication is received, we'll send a message back to the sender
	// to let them know it was successful.
	await sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
async function receivedMessage(event) {
	var senderID = event.sender.id;
	var recipientID = event.recipient.id;
	var timeOfMessage = event.timestamp;
	var message = event.message;

	console.log("Received message for user %d and page %d at %d with message:",
		senderID, recipientID, timeOfMessage);
	console.log(JSON.stringify(message));

	var isEcho = message.is_echo;
	var messageId = message.mid;
	var appId = message.app_id;
	var metadata = message.metadata;

	// You may get a text or attachment but not both
	var messageText = message.text;
	var messageAttachments = message.attachments; // like, emoji, other non-texts
	var quickReply = message.quick_reply;

	if (isEcho) {
		console.log("Received echo for message %s and app %d with metadata %s", messageId, appId, metadata);
		return;
	} else if (quickReply) {
		console.log("Quick reply for message %s with payload %s", messageId, quickReplyPayload);

		await sendTypingIndicator(senderID, true);
		await httpGet(senderID, quickReply.payload);
		await sendTypingIndicator(senderID, false);
		return;
	}

	if(!messageText && messageAttachments) {
		await sendTextMessage(senderID, "Search the Internet for free! You may also get the text contents of a website by sending us the complete http link (e.g. \"https://phmountains.com\").");
		return;
	}

	if (messageText.startsWith("http://") || messageText.startsWith("https://")) {
		await sendTypingIndicator(senderID, true);
		await httpGet(senderID, messageText);
		await sendTypingIndicator(senderID, false);
		return;
	}

	try {
		await sendTypingIndicator(senderID, true);

		const obj = await rp.get({
			uri: SEARCH_URL + messageText,
			json: true
		});

		let index = 1,
			total = "",
			links = [];

		if(!obj.items) {
			console.log("Googled " + messageText + ": ZERO results");
			await sendTextMessage(senderID, "Thanks for trying out this bot. Please bear with us as we already exceeded the total daily number of searches allowable by Google (by a single app). The bot will work again at 4 p.m. Philippine time when Google resets the daily limit.\n\nIn the meantime, you may also use this as a primitive web browser. Just send a link (e.g. \"http://phmountains.com\") and the bot will respond with the text-only version of the website.");
			return;
		}

		obj.items.forEach(function (item) {
			if (index != 1) total += "\n\n";

			total += (index++) + ". " + item.title + "\n\n" + item.snippet;
			links.push(item.link);
		});

		console.log("Googled " + messageText + ": " + obj.items.length + " results");

		await sendTextMessage(senderID, total);
		await sendQuickReply(senderID, "Choose a search result:", links);
	} catch(err) {
		console.error("Error: " + err.message);
		await sendTextMessage(senderID, "Oops! An error was encountered. Please try again.");
	} finally {
		await sendTypingIndicator(senderID, false);
	}
}

/*
 * Send a text message using the Send API.
 *
 */
async function sendTextMessage(recipientId, messageText) {
	const chunks = messageText.match(/[\s\S]{1,2000}/g),
		results = [];

	for(let i = 0; i < chunks.length; ++i) {
		results.push(await callSendAPI(recipientId, {
			message: {
				text: chunks[i]
			}
		}));
	}

	return results;
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
async function sendQuickReply(recipientId, message, urlArray) {
	var messageData = {
		message: {
			text: message,
			quick_replies: []
		}
	};

	for(let i = 1; i <= 10; ++i) {
		messageData.message.quick_replies.push({
			content_type: "text",
			title: i,
			payload: urlArray[i - 1]
		});
	}

	return await callSendAPI(recipientId, messageData);
}

async function sendTypingIndicator(recipientId, status) {
	console.log(`Turning typing indicator ${status ? "on" : "off"}`);

	return await callSendAPI(recipientId, {
		sender_action: status ? "typing_on" : "typing_off"
	});
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
async function callSendAPI(recipientId, messageData) {
	return await rp.post({
		uri: 'https://graph.facebook.com/v2.6/me/messages',
		qs: {
			access_token: PAGE_ACCESS_TOKEN
		},
		json: Object.assign({}, messageData, {
			recipient: {
				id: recipientId
			}
		})
	});
}

async function httpGet(senderID, url) {
	console.log("httpGet: Fetching: %s", url);
	request({
		uri: url,
		method: 'GET'

	}, async function (error, response, body) {
		if (!error && response.statusCode == 200) {
			console.log("httpGet: Successfully received response from: %s",
				url);

			var text = sanitizeHtml(body, {
				allowedTags: [],
				allowedAttributes: {},
				allowedIframeHostnames: []
			});

			await sendTextMessage(senderID, text);
		} else {
			console.error("Failed calling httpGet from: %s", url);
		}
	});
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function () {
	console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
