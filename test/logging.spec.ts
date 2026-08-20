import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker, { logAssessment } from '../src/index';

// The monocle client is mocked so both verify paths can be driven to a real
// assessment without valid crypto material or network access. This lives in
// its own spec file so the mock cannot leak into the SELF-based integration
// tests in index.spec.ts (each test file gets a fresh module graph).
const mockClient = vi.hoisted(() => ({
	evaluateAssessment: vi.fn(),
	decryptAssessment: vi.fn(),
}));

vi.mock('@spur.us/monocle-backend', async importOriginal => {
	const actual = await importOriginal<typeof import('@spur.us/monocle-backend')>();
	return {
		...actual,
		createMonocleClient: vi.fn(async () => mockClient),
	};
});

function buildAssessment() {
	return {
		vpn: false,
		proxied: false,
		anon: false,
		rdp: false,
		dch: false,
		cc: 'US',
		ip: '192.0.2.1',
		ipv6: '',
		ts: new Date().toISOString(), // fresh, so the decrypt path takes the allow branch
		complete: true,
		id: 'test-assessment-id',
		sid: 'test-sid',
	};
}

function buildValidateRequest() {
	return new Request('https://example.com/validate_captcha', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-MCL-Validate': '1',
			'CF-Connecting-IP': '127.0.0.1',
		},
		body: JSON.stringify({ captchaData: 'test_captcha_data' }),
	});
}

// Only the lines this feature emits; the worker (and runtime) may log other things.
function assessmentLogLines(spy: ReturnType<typeof vi.spyOn>) {
	return spy.mock.calls
		.map(args => args[0])
		.filter((arg): arg is string => typeof arg === 'string' && arg.startsWith('{"monocle":"assessment"'));
}

describe('assessment logging', () => {
	let logSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		logSpy = vi.spyOn(console, 'log');
		mockClient.decryptAssessment.mockResolvedValue(buildAssessment());
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('should not log the assessment by default (LOG_ASSESSMENT unset)', async () => {
		const response = await worker.fetch(buildValidateRequest() as never, env);

		expect(response.status).toBe(200);
		expect(assessmentLogLines(logSpy)).toHaveLength(0);
	});

	it('should not log the assessment for values other than exactly "true"', async () => {
		const response = await worker.fetch(buildValidateRequest() as never, { ...env, LOG_ASSESSMENT: 'TRUE' });

		expect(response.status).toBe(200);
		expect(assessmentLogLines(logSpy)).toHaveLength(0);
	});

	it('should log one JSON line with the assessment on the decrypt path when enabled', async () => {
		const assessment = buildAssessment();
		mockClient.decryptAssessment.mockResolvedValue(assessment);

		const response = await worker.fetch(buildValidateRequest() as never, { ...env, LOG_ASSESSMENT: 'true' });

		expect(response.status).toBe(200);
		const lines = assessmentLogLines(logSpy);
		expect(lines).toHaveLength(1);
		expect(JSON.parse(lines[0])).toEqual({ monocle: 'assessment', assessment });
	});

	it('should log decision fields and the assessment on the policy path, even when denied', async () => {
		const assessment = buildAssessment();
		mockClient.evaluateAssessment.mockResolvedValue({
			allowed: false,
			assessment,
			decisionId: 'test-decision-id',
			reason: 'test-deny-reason',
		});

		const response = await worker.fetch(buildValidateRequest() as never, {
			...env,
			USE_POLICY_API: 'true',
			LOG_ASSESSMENT: 'true',
		});

		expect(response.status).toBe(403); // denied, yet still logged
		const lines = assessmentLogLines(logSpy);
		expect(lines).toHaveLength(1);
		expect(JSON.parse(lines[0])).toEqual({
			monocle: 'assessment',
			allowed: false,
			decisionId: 'test-decision-id',
			reason: 'test-deny-reason',
			assessment,
		});
	});

	it('should log nothing when the policy API withholds the assessment', async () => {
		// An org without the logging entitlement gets a decision with no
		// assessment, so there is nothing worth writing a line about.
		mockClient.evaluateAssessment.mockResolvedValue({
			allowed: true,
			decisionId: 'test-decision-id',
			reason: 'test-reason',
		});

		const response = await worker.fetch(buildValidateRequest() as never, {
			...env,
			USE_POLICY_API: 'true',
			LOG_ASSESSMENT: 'true',
		});

		expect(response.status).toBe(200); // the verdict still stands
		expect(assessmentLogLines(logSpy)).toHaveLength(0);
	});

	it('should never throw, even for an unserializable payload', () => {
		const circular: Record<string, unknown> = {};
		circular.self = circular;

		expect(() => logAssessment({ ...env, LOG_ASSESSMENT: 'true' }, circular)).not.toThrow();
		expect(assessmentLogLines(logSpy)).toHaveLength(0);
	});
});
