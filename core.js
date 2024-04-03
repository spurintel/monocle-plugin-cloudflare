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


/*
This route demonstrates path parameters, allowing you to extract fragments from the request
URL.

Try visit /example/hello and see the response.
*/
export function captchaPage(request, env) {

	// Return the HTML with the string to the client
	return new Response(captcha.replace('SITE_TOKEN', env.SITE_TOKEN), {
		headers: {
			'Content-Type': 'text/html',
		},
	});
}

export function deniedPage(request, env) {
	let basicText = 'any VPNs or proxies and try again';
	const url = new URL(request.url);

	// Get the query parameter by name, e.g., "param"
	const paramValue = url.searchParams.get('service');
	if (paramValue && paramValue !== "") {
		basicText = paramValue;
	}
	// Return the HTML with the string to the client
	return new Response(denied.replace('REPLACE_ME', basicText), {
		headers: {
			'Content-Type': 'text/html',
		},
	});
}
export async function primaryHandler(request, env) {
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
}

export async function setSecureCookie(request, env) {
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

export async function validateCookie(request, env) {
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
