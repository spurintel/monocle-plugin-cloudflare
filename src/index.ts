import { COOKIE_NAME, EXEMPTED_SERVICES } from './constants';
import { parseCookies, validateCookie, setSecureCookie } from './cookies';
import captcha from './templates/captcha_page.html';
import { createMonocleClient } from '@spur.us/monocle-backend';

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
	try {
		const monocle = await createMonocleClient({ secretKey: env.SECRET_KEY });
		const body = (await request.json()) as { captchaData: string };

		let privateKeyPem: string | undefined;
		if (env.PRIVATE_KEY && env.PRIVATE_KEY.length > 0) {
			privateKeyPem = env.PRIVATE_KEY;
		}

		const assessment = await monocle.decryptAssessment(body.captchaData, {
			privateKeyPem,
		});

		const responseTime = new Date(assessment.ts);
		const currentTime = new Date();
		const timeDifference = currentTime.getTime() - responseTime.getTime();
		const timeDifferenceInSeconds = timeDifference / 1000;

		if (
			(timeDifferenceInSeconds > 5 || assessment.anon) &&
			!EXEMPTED_SERVICES.includes(assessment.service)
		) {
			return new Response(assessment.service, { status: 403 });
		}

		const headers = await setSecureCookie(request, env);
		return new Response('Captcha validated successfully', { status: 200, headers: headers });
	} catch (error: unknown) {
		const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
		console.error(
			`Error verifying bundle with https://decrypt.mcl.spur.us/api/v1/assessment: ${errorMessage}`
		);
		return new Response(
			`Error verifying bundle with https://decrypt.mcl.spur.us/api/v1/assessment: ${errorMessage}`,
			{ status: 400 }
		);
	}
}
