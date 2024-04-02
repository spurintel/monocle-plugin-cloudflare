import { Router } from 'itty-router';
import captcha from './captcha_page.html';
import denied from './denied.html';

// Helper function to parse cookies from the request headers
function parseCookies(header) {
	let list = {}
	if (!header) return list
	header.split(';').forEach(cookie => {
		let [name, ...rest] = cookie.split('=')
		name = name?.trim()
		if (name) {
			list[name] = rest.join('=').trim()
		}
	})
	return list
}


// Create a new router
const router = Router();

/*
This route demonstrates path parameters, allowing you to extract fragments from the request
URL.

Try visit /example/hello and see the response.
*/
router.get('/captcha_page.html', (request, env) => {

	// Return the HTML with the string to the client
	return new Response(captcha.replace('SITE_TOKEN', env.SITE_TOKEN), {
		headers: {
			'Content-Type': 'text/html',
		},
	});
});

router.get('/denied', () => {

	// Return the HTML with the string to the client
	return new Response(denied, {
		headers: {
			'Content-Type': 'text/html',
		},
	});
});

/*
This shows a different HTTP method, a POST.

Try send a POST request using curl or another tool.

Try the below curl command to send JSON:

$ curl -X POST <worker> -H "Content-Type: application/json" -d '{"abc": "def"}'
*/
router.post('/validate_captcha', async (request, env) => {
	// Define the URL of the third-party API
	const thirdPartyApiUrl = 'https://decrypt.mcl.spur.us/api/v1/assessment';

	try {
		// Assuming the incoming request's body is JSON and contains captchaData
		const requestData = await request.json();
		const captchaData = requestData.captchaData;
		// Prepare the request to the third-party API
		const apiResponse = await fetch(thirdPartyApiUrl, {
			method: 'POST',
			body: captchaData,
			headers: {
				'Content-Type': 'text/plain',
				// Token should be securely stored and retrieved; adjust as needed
				'Token': env.VERIFY_TOKEN,
			},
		});

		if (!apiResponse.ok) {
			throw new Error(`API call failed: ${apiResponse.statusText}`);
		}
		const data = await apiResponse.json();

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
router.all('*', async (request, env) => {
	const url = new URL(request.url)
	const cookies = parseCookies(request.headers.get('Cookie'))
	const clientIpAddress = request.headers.get('CF-Connecting-IP') // Cloudflare specific header for client IP

	// Check if the secure cookie is present and valid
	if (cookies.MCLVALID && await validateCookie(request, env)) {
		// If the MCLVALID cookie is present and valid, proceed with the original request
		// Internal redirect logic here (modify as needed)
		return fetch(request) // Simply proxy the request in this example
	} else {
		// If no valid cookie, redirect to the captcha page
		return Response.redirect(`${url.protocol}//${url.host}/captcha_page.html?uri=${url.pathname}`, 302)
	}
});


async function setSecureCookie(request, env) {
	const clientIpAddress = request.headers.get('CF-Connecting-IP');
	const expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
	const cookieValue = `${clientIpAddress}|${expiryTime}`;

	// Assuming `cookieSecret` is securely stored and retrieved; adjust as necessary.
	const secretKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(env.COOKIE_SECRET_VALUE), // Replace YOUR_COOKIE_SECRET with your actual secret
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const signature = await crypto.subtle.sign(
		"HMAC",
		secretKey,
		new TextEncoder().encode(cookieValue)
	);

	const signedValue = `${cookieValue}:${bufToHex(new Uint8Array(signature))}`;

	// Return the Set-Cookie header so it can be added to a response
	const headers = new Headers()
	headers.append('Set-Cookie', `MCLVALID=${signedValue}; Secure; HttpOnly; Path=/; SameSite=Strict`)
	return headers;
}

async function validateCookie(request, env) {
	const cookieHeader = request.headers.get('Cookie');
	if (!cookieHeader) {
		return false;
	}

	// Extract the MCLVALID cookie value
	const cookies = cookieHeader.split(';').map(c => c.trim());
	const mclValidCookie = cookies.find(c => c.startsWith('MCLVALID='));
	if (!mclValidCookie) {
		return false;
	}

	const cookieValue = mclValidCookie.split('=')[1];
	const parts = cookieValue.split(':');
	if (parts.length !== 2) {
		return false;
	}

	const [payload, receivedSignature] = parts;
	const [value, expiryTime] = payload.split('|');

	const clientIpAddress = request.headers.get('CF-Connecting-IP');
	if (value != clientIpAddress) {
		return false;
	}
	// Check if the cookie has expired
	if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime, 10)) {
		return false;
	}

	// Validate the signature
	const secretKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(env.COOKIE_SECRET_VALUE), // Replace YOUR_COOKIE_SECRET with your actual secret
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const expectedSignature = await crypto.subtle.sign(
		"HMAC",
		secretKey,
		new TextEncoder().encode(`${value}|${expiryTime}`)
	);

	// Compare hex strings
	if (bufToHex(new Uint8Array(expectedSignature)) !== receivedSignature) {
		return false;
	}

	return true;
}

// Use the same bufToHex function defined above


// Helper function to convert ArrayBuffer to hex
function bufToHex(buffer) {
	return Array.prototype.map.call(buffer, x => x.toString(16).padStart(2, '0')).join('');
}

export default {
	fetch: router.handle,
};
