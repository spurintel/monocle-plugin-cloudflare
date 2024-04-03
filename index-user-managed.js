import { Router } from 'itty-router';
import { setSecureCookie, deniedPage, captchaPage, primaryHandler } from './core';
const jose = require("jose");

// Create a new router
const router = Router();

/*
This route demonstrates path parameters, allowing you to extract fragments from the request
URL.

Try visit /example/hello and see the response.
*/
router.get('/captcha_page.html', captchaPage);

router.get('/denied', deniedPage);

/*
This shows a different HTTP method, a POST.

Try send a POST request using curl or another tool.

Try the below curl command to send JSON:

$ curl -X POST <worker> -H "Content-Type: application/json" -d '{"abc": "def"}'
*/
router.post('/validate_captcha', async (request, env) => {
	// Define the URL of the third-party API
	try {
		// Assuming the incoming request's body is JSON and contains captchaData
		const requestData = await request.json();
		const captchaData = requestData.captchaData;

		// load private key into a KeyLike type as jose expects
		const privateKey = await jose.importPKCS8(env.PRIVATE_KEY, "ECDH-ES");

		// decrypted plaintext is a Buffer and will need decoding
		const decoder = new TextDecoder();

		// decrypt the bundle
		const decryptResult = await jose.compactDecrypt(captchaData, privateKey);

		// decode the plaintext Buffer and parse back to JSON
		const data = JSON.parse(decoder.decode(decryptResult.plaintext));


		// Assuming you have a way to get the client's IP address, if needed
		// Cloudflare Workers provide `request.headers.get('CF-Connecting-IP')` for the client's IP
		const clientIpAddress = request.headers.get('CF-Connecting-IP');

		// Parse the timestamp from the response and calculate the difference
		const responseTime = new Date(data.ts);
		const currentTime = new Date();
		const timeDifference = Math.abs(currentTime - responseTime) / 1000;

		// Check if the time difference is within 5 seconds and other conditions
		if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
			return new Response(JSON.stringify(data), { status: 403 });
		}

		// If validation is successful, you might want to set a cookie or similar here
		// Example: return new Response("Success", { status: 200, headers: {'Set-Cookie': 'your-cookie-setup'} });
		let headers = await setSecureCookie(request, env);

		return new Response("Captcha validated successfully", { status: 200, headers: headers });
	} catch (error) {
		console.error(`Error calling third-party API: ${error.message}`);
		return new Response("Internal Server Error", { status: 500 });
	}
});

/*
This is the last route we define, it will match anything that hasn't hit a route we've defined
above, therefore it's useful as a 404 (and avoids us hitting worker exceptions, so make sure to include it!).

Visit any page that doesn't exist (e.g. /foobar) to see it in action.
*/
router.all('*', primaryHandler);


export default {
	fetch: router.handle,
};
