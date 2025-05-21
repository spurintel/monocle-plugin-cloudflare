import { COOKIE_NAME, EXEMPTED_SERVICES } from './constants';
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
			baseDomain: 'mcl.spur.dev',
		});
		const body = (await request.json()) as { captchaData: string };

		const policyDecision = await monocle.evaluateAssessment(body.captchaData);

		if (!policyDecision.allowed) {
			return new Response(policyDecision.reason, { status: 403 });
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
