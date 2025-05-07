/**
 * Parses a cookie header string into a record of cookie name-value pairs.
 * @param {string | null} header - The cookie header string to parse
 * @returns {Record<string, string>} A record containing cookie names as keys and their values
 */
export function parseCookies(header: string | null): Record<string, string> {
	let list: Record<string, string> = {};
	if (!header) return list;
	header.split(';').forEach(cookie => {
		let [name, ...rest] = cookie.split('=');
		name = name?.trim();
		if (name) {
			list[name] = rest.join('=').trim();
		}
	});
	return list;
}

/**
 * Sets a secure cookie with encrypted client IP and expiry time.
 * @param {Request} request - The incoming request object
 * @param {Env} env - Environment containing the cookie secret value
 * @returns {Promise<Headers>} Headers object with Set-Cookie header
 */
export async function setSecureCookie(request: Request, env: Env) {
	const clientIpAddress =
		request.headers.get('CF-Connecting-IP') || request.headers.get('X-Real-IP');
	if (!clientIpAddress) {
		console.log('ERROR: No client IP found in headers.');
		console.log(JSON.stringify([...request.headers]));
	}
	const expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
	const cookieValue = `${clientIpAddress}|${expiryTime}`;

	const secretKey = await crypto.subtle.importKey(
		'raw',
		hexToBuf(env.COOKIE_SECRET_VALUE),
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt']
	);

	const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a random initialization vector

	const encryptedValue = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: iv },
		secretKey,
		new TextEncoder().encode(cookieValue)
	);

	const encryptedValueHex = bufToHex(new Uint8Array(encryptedValue));
	const ivHex = bufToHex(iv);

	const headers = new Headers();
	headers.append(
		'Set-Cookie',
		`MCLVALID=${ivHex}.${encryptedValueHex}; Secure; HttpOnly; Path=/; SameSite=Lax`
	);
	return headers;
}

/**
 * Validates the secure cookie against the client's IP and expiry time.
 * @param {Request} request - The incoming request object
 * @param {Env} env - Environment containing the cookie secret value
 * @returns {Promise<boolean>} Promise resolving to boolean indicating if cookie is valid
 */
export async function validateCookie(request: Request, env: Env): Promise<boolean> {
	const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Real-IP');
	if (!clientIp) {
		console.log('ERROR: No client IP found in headers.');
		console.log(JSON.stringify([...request.headers]));
	}
	const cookieHeader = request.headers.get('Cookie');
	if (!cookieHeader) {
		return false;
	}

	const cookies = cookieHeader.split(';').map((c: string) => c.trim());
	const mclValidCookie = cookies.find((c: string) => c.startsWith('MCLVALID='));
	if (!mclValidCookie) {
		return false;
	}

	const cookieValue = mclValidCookie.split('=')[1];
	const [ivHex, encryptedValueHex] = cookieValue.split('.');
	if (!ivHex || !encryptedValueHex) {
		return false;
	}

	const secretKey = await crypto.subtle.importKey(
		'raw',
		hexToBuf(env.COOKIE_SECRET_VALUE),
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt']
	);
	var clientIpAddress, expiryTime;
	try {
		const decryptedValue = await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: hexToBuf(ivHex) },
			secretKey,
			hexToBuf(encryptedValueHex)
		);

		[clientIpAddress, expiryTime] = new TextDecoder().decode(decryptedValue).split('|');
	} catch (error) {
		console.log(`Error with decrypt: ${error}`);
		return false;
	}
	if (clientIp !== clientIpAddress) {
		console.log(`Mismatch IP address. Expecting ${clientIpAddress}, Got ${clientIp}`);
		return false;
	}

	if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime, 10)) {
		console.log(`Cookie has expired.`);
		return false;
	}

	return true;
}

/**
 * Converts a Uint8Array buffer to a hexadecimal string.
 * @param {Uint8Array} buffer - The buffer to convert
 * @returns {string} Hexadecimal string representation of the buffer
 */
function bufToHex(buffer: Uint8Array) {
	return Array.prototype.map.call(buffer, x => x.toString(16).padStart(2, '0')).join('');
}

/**
 * Converts a hexadecimal string to a Uint8Array buffer.
 * @param {string} hex - The hexadecimal string to convert
 * @returns {Uint8Array} Uint8Array buffer representation of the hex string
 */
function hexToBuf(hex: string) {
	const matches = hex.match(/.{1,2}/g);
	if (!matches) return new Uint8Array();
	return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
}
