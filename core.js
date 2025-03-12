import captcha from './captcha_page.html';
import denied from './denied.html';
import error from './error.html';

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

export function captchaPage(request, env) {
	// Return the HTML with the string to the client
	return new Response(captcha.replace('PUBLISHABLE_KEY', env.PUBLISHABLE_KEY), {
		headers: {
			'Content-Type': 'text/html',
		},
	});
}

export function deniedPage(request, env) {
	let basicText = 'any VPNs or proxies and try again';
	const url = new URL(request.url);
	const paramValue = url.searchParams.get('service');
	if (paramValue && paramValue !== "") {
		basicText = paramValue;
	}
	basicText = escapeHtml(basicText);
	// Return the HTML with the string to the client
	return new Response(denied.replace('REPLACE_ME', basicText), {
		status: 403,
		headers: {
			'Content-Type': 'text/html',
		},
	});
}

export function errorPage(request, env) {
	let basicText = 'any VPNs or proxies and try again';
	const url = new URL(request.url);
	const paramValue = url.searchParams.get('err');
	if (paramValue && paramValue !== "") {
		basicText = paramValue;
	}
	basicText = escapeHtml(basicText);
	// Return the HTML with the string to the client
	return new Response(error.replace('REPLACE_ME', basicText), {
		status: 400,
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
	headers.append('Set-Cookie', `MCLVALID=${ivHex}.${encryptedValueHex}; Secure; HttpOnly; Path=/; SameSite=Strict`);
	return headers;
}

export async function validateCookie(request, env) {
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

	const decryptedValue = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: hexToBuf(ivHex) },
		secretKey,
		hexToBuf(encryptedValueHex)
	);

	const [clientIpAddress, expiryTime] = new TextDecoder().decode(decryptedValue).split('|');

	if (request.headers.get('CF-Connecting-IP') !== clientIpAddress) {
		return false;
	}

	if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime, 10)) {
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
