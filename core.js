import captcha from './captcha_page.html';

// Replace these variables if there are other services you wish to allow access to your service
export const EXEMPTED_SERVICES = ['WARP_VPN', 'ICLOUD_RELAY_PROXY'];

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


// Function to escape HTML characters to prevent XSS
function escapeHtml(str) {
	if (!str) return '';
	return str
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

export async function primaryHandler(request, env) {
	const url = new URL(request.url)
	const cookies = parseCookies(request.headers.get('Cookie'))

	// Check if the secure cookie is present and valid
	if (cookies.MCLVALID && await validateCookie(request, env)) {
		// If the MCLVALID cookie is present and valid, proceed with the original request
		return fetch(request) // Simply proxy the request in this example
	} else {
		// Return the HTML with the string to the client
		return new Response(captcha.replace('PUBLISHABLE_KEY', env.PUBLISHABLE_KEY).replace('REPLACE_REDIRECT', url.href), {
			headers: {
				'Content-Type': 'text/html',
			},
		});
	}
}

export async function setSecureCookie(request, env) {
	const clientIpAddress = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Real-IP");
	if (!clientIpAddress) {
		console.log("ERROR: No client IP found in headers.");
		console.log(JSON.stringify([...request.headers]));
	}
	const expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
	const cookieValue = `${clientIpAddress}|${expiryTime}`;

	const secretKey = await crypto.subtle.importKey(
		"raw",
		hexToBuf(env.COOKIE_SECRET_VALUE),
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"]
	);

	const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a random initialization vector

	const encryptedValue = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: iv },
		secretKey,
		new TextEncoder().encode(cookieValue)
	);

	const encryptedValueHex = bufToHex(new Uint8Array(encryptedValue));
	const ivHex = bufToHex(iv);

	const headers = new Headers();
	headers.append('Set-Cookie', `MCLVALID=${ivHex}.${encryptedValueHex}; Secure; HttpOnly; Path=/; SameSite=Lax`);
	return headers;
}

export async function validateCookie(request, env) {
	const clientIp = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Real-IP");
	if (!clientIp) {
		console.log("ERROR: No client IP found in headers.");
		console.log(JSON.stringify([...request.headers]));
	}
	const cookieHeader = request.headers.get('Cookie');
	if (!cookieHeader) {
		return false;
	}

	const cookies = cookieHeader.split(';').map(c => c.trim());
	const mclValidCookie = cookies.find(c => c.startsWith('MCLVALID='));
	if (!mclValidCookie) {
		return false;
	}

	const cookieValue = mclValidCookie.split('=')[1];
	const [ivHex, encryptedValueHex] = cookieValue.split('.');
	if (!ivHex || !encryptedValueHex) {
		return false;
	}

	const secretKey = await crypto.subtle.importKey(
		"raw",
		hexToBuf(env.COOKIE_SECRET_VALUE),
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"]
	);
	try {
		const decryptedValue = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: hexToBuf(ivHex) },
			secretKey,
			hexToBuf(encryptedValueHex)
		);

		const [clientIpAddress, expiryTime] = new TextDecoder().decode(decryptedValue).split('|');
	} catch (error) {
		return false;
	}
	if (clientIp !== clientIpAddress) {
		console.log(`Mismatch IP address. Expecting ${clientIpAddress}, Got ${clientIp}`)
		return false;
	}

	if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime, 10)) {
		console.log(`Cookie has expired.`)
		return false;
	}

	return true;
}

function bufToHex(buffer) {
	return Array.prototype.map.call(buffer, x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex) {
	return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
