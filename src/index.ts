import { COOKIE_NAME, DEFAULT_EXEMPTED_SERVICES } from './constants';
import { parseCookies, validateCookie, setSecureCookie } from './cookies';
import captcha from './templates/captcha_page.html';
import {
	createMonocleClient,
	MonocleAPIError,
	MonocleDecryptionError,
} from '@spur.us/monocle-backend';

/**
 * Cloudflare Worker that handles captcha validation and request routing
 */
export default {
	/**
	 * Main request handler for the Cloudflare Worker.
	 * @param {Request} request - The incoming request
	 * @param {Env} env - Worker environment variables
	 * @returns {Promise<Response>} Response object
	 */
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// This is the endpoint that the captcha will call to validate the captcha.
		if (url.pathname === '/validate_captcha' && request.method === 'POST') {
			return validateCaptchaHandler(request, env);
		}

		const cookies = parseCookies(request.headers.get('Cookie'));

		// If the cookie is set, return the original request
		if (cookies[COOKIE_NAME] && (await validateCookie(request, env))) {
			return fetch(request);
		}

		return new Response(
			captcha.replace('PUBLISHABLE_KEY', env.PUBLISHABLE_KEY).replace('REPLACE_REDIRECT', url.href),
			{
				headers: {
					'Content-Type': 'text/html',
				},
			}
		);
	},
} satisfies ExportedHandler<Env>;

/**
 * Handles captcha validation requests.
 * @param {Request} request - The incoming request containing captcha data
 * @param {Env} env - Worker environment variables
 * @returns {Promise<Response>} Response indicating validation success or failure
 */
async function validateCaptchaHandler(request: Request, env: Env): Promise<Response> {
	let privateKeyPem: string | undefined;
	if (env.PRIVATE_KEY && env.PRIVATE_KEY.length > 0) {
		privateKeyPem = env.PRIVATE_KEY;
	}

	try {
		const monocle = await createMonocleClient({
			secretKey: env.SECRET_KEY,
			baseDomain: 'mcl.spur.us',
		});
		const body = (await request.json()) as { captchaData: string };

		const policyDecision = await monocle.evaluateAssessment(body.captchaData);

		if (!policyDecision.allowed && env.MODE !== 'MONITOR') {
			return buildBlockResponse(env);
		}

		const headers = await setSecureCookie(request, env);
		return new Response('Captcha validated successfully', { status: 200, headers: headers });
	} catch (error: unknown) {
		let errorMessage: string;

		if (error instanceof MonocleAPIError) {
			console.error(
				`Error evaluating assessment with https://decrypt.mcl.spur.us/api/v1/policy: ${error.message}`
			);
		} else if (error instanceof Error) {
			console.error(`Error evaluating assessment: ${error.message}`);
		} else {
			errorMessage = 'Unknown error occurred';
		}

		return new Response('Error evaluating assessment', { status: 400 });
	}
}

/**
 * Builds the block response based on worker env config.
 * Defaults to a plain 403 HTML page if no config is present.
 */
/**
 * Builds the block response based on worker env config.
 * Sets X-Block-Action header so the captcha page JS can handle it correctly:
 *   - "redirect:<url>" → captcha JS navigates window.location
 *   - "html"          → captcha JS replaces the document with the HTML body
 * Falls back to a plain 403 text response if no config is set.
 */
function buildBlockResponse(env: Env): Response {
	if (env.BLOCK_RESPONSE_TYPE === 'redirect' && env.BLOCK_REDIRECT_URL) {
		return new Response(null, {
			status: 403,
			headers: { 'X-Block-Action': `redirect:${env.BLOCK_REDIRECT_URL}` },
		});
	}

	const statusCode = parseInt(env.BLOCK_STATUS_CODE ?? '403', 10);
	const title = env.BLOCK_PAGE_TITLE ?? 'Access Denied';
	const body = env.BLOCK_RESPONSE_BODY ?? 'This request has been blocked.';

	const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${title}</title>
  <style>
    body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fff;color:#111}
    .container{text-align:center;max-width:500px;padding:2rem}
    h1{font-size:1.5rem;font-weight:300;margin-bottom:1rem}
    p{color:#6b7280}
  </style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <p>${body}</p>
  </div>
</body>
</html>`;

	return new Response(html, {
		status: statusCode,
		headers: {
			'Content-Type': 'text/html',
			'X-Block-Action': 'html',
		},
	});
}
