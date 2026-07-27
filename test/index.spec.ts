import { describe, it, expect } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import { setSecureCookie } from '../src/cookies';
import { buildBlockResponse } from '../src/index';

describe('Cloudflare Worker', () => {
	it('should return captcha page for requests without valid cookie', async () => {
		const request = new Request('https://example.com');
		const response = await SELF.fetch(request);

		expect(response.status).toBe(200);
		expect(response.headers.get('Content-Type')).toBe('text/html');
		const text = await response.text();
		expect(text).toContain('test_publishable_key');
	});

	it('should reject validation requests without captcha data', async () => {
		const request = new Request('https://example.com/validate_captcha', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'X-MCL-Validate': '1' },
			body: JSON.stringify({}),
		});

		const response = await SELF.fetch(request);
		expect(response.status).toBe(400);
	});

	it('should handle decryptAssessment errors', async () => {
		const request = new Request('https://example.com/validate_captcha', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'X-MCL-Validate': '1' },
			body: JSON.stringify({ captchaData: 'invalid_captcha_data' }),
		});

		// Undecryptable assessments are the one verification failure that blocks
		// rather than failing open: the data is bad, not the API.
		const response = await SELF.fetch(request);
		expect(response.status).toBe(403);
		const text = await response.text();
		expect(text).toContain('Blocked');
	});

	it('should render the redirect URL verbatim when it contains $-patterns', async () => {
		// $& and $` are substitution directives for String.replaceAll with a string
		// replacement; the function replacement must insert the URL literally.
		const href = new URL('https://example.com/?next=$&q=$`').href;
		const response = await SELF.fetch(new Request(href));

		expect(response.status).toBe(200);
		const text = await response.text();
		expect(text).toContain(JSON.stringify(href));
		expect(text).not.toContain('REPLACE_REDIRECT');
	});

	it('should fall back to 403 when BLOCK_STATUS_CODE cannot be used as a block status', () => {
		// Out-of-range statuses (and 204, which forbids a body) would make
		// `new Response` throw inside the fail-open try, turning a DENY into an ALLOW.
		for (const code of ['999', '99', '204']) {
			const response = buildBlockResponse({ ...env, BLOCK_STATUS_CODE: code });
			expect(response.status).toBe(403);
		}
	});

	it('should use BLOCK_STATUS_CODE when it is a valid error status', () => {
		const response = buildBlockResponse({ ...env, BLOCK_STATUS_CODE: '451' });
		expect(response.status).toBe(451);
	});

	it('should allow requests with valid cookie', async () => {
		const clientIp = '127.0.0.1';
		const request = new Request('https://example.com', {
			headers: {
				'CF-Connecting-IP': clientIp,
			},
		});
		const headers = await setSecureCookie(request, env);
		const cookie = headers.get('Set-Cookie')?.split(';')[0].split('=')[1];

		const requestWithCookie = new Request('https://example.com', {
			headers: {
				'Cookie': `MCLVALID=${cookie}`,
				'CF-Connecting-IP': clientIp,
			},
		});

		const response = await SELF.fetch(requestWithCookie);
		expect(response.status).toBe(200);
		const text = await response.text();
		expect(text).toContain('Example Domain');
	});
});
