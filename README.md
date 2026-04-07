# Monocle by Spur

Easily deploy a Cloudflare Worker with Monocle that will automatically protect your site from residential proxies, malware proxies, or other commercial anonymity services.

## Description

Monocle can detect a user session coming from a residential proxy, malware proxy, or other endpoint based proxy network. By detecting this at the session level, you can take action on abusive users without impacting legitimate ones.

[Monocle](https://spur.us/platform/session-enrichment)
[Docs](https://docs.spur.us/#/monocle)
[FAQ](https://spur.us/platform/session-enrichment)
[Demo](https://spur.us/demo)
[Blog](https://spur.us/blog)

This Cloudflare Worker will automatically force a Monocle assessment on new users before allowing them access to your site. Authentic users will not be negatively impacted. The cookie this plugin sets is valid for one hour or until the user changes IP address.

## Help and Support

support@spur.us

---

## Deployment Options

### Option 1 — No-Code Deploy (Recommended)

Deploy and manage the worker directly from the [Monocle Cloudflare admin page](https://app.spur.us/monocle/onboard) without any manual configuration. The admin page handles all secrets, routing, and policy configuration automatically.

**Features available via the dashboard:**
- Monitor Mode — passively assess all traffic with no blocking
- Enforcement Mode — block traffic based on your Monocle Policy
- Configurable block responses (custom messaging or redirect URL)

### Option 2 — Manual Deploy

Deploy and manage the worker yourself using Wrangler.

#### Terraform

Use our official [Terraform module](https://registry.terraform.io/modules/spurintel/worker-spur-monocle/cloudflare/latest) to quickly integrate the Monocle Cloudflare worker into your Terraform-enabled project.

#### Wrangler Setup

**Install Wrangler CLI**

Wrangler is the Cloudflare CLI tool that allows you to manage your Cloudflare Workers.
In order to install the Monocle worker make sure you have `wrangler` installed globally.

```sh
npm install -g wrangler
```

Make sure you are logged in to your Cloudflare account with Wrangler.

```sh
wrangler login
```

**Fork this repository**

In order to deploy this worker, you will need to fork this repository to your own GitHub account.
This will allow you to make changes to the worker and deploy it to your own Cloudflare account.

1. Navigate to the [GitHub repository](https://github.com/spurintel/monocle-plugin-cloudflare) for this worker.
2. In the top-right corner of the page, click the **Fork** button.
3. You will now have a copy of this repository in your own GitHub account.
4. You can clone this repository to your local machine by running the following command:

```sh
git clone git@github.com:${YOUR_USERNAME_HERE}/monocle-plugin-cloudflare.git
cd monocle-plugin-cloudflare
npm install # Install dependencies
```

**Configure the worker**

You will need to create a `wrangler.toml` file and set your `account_id` and `route`.

1. Open the `wrangler.toml` file in your text editor.
2. Copy the example below and paste it into the `wrangler.toml` file.
3. Update the `compatibility_date` field with the current date. This value must be greater than `2024-11-11`.
4. Add `nodejs_compat` to `compatibility_flags`.
5. Update the `account_id` field with your Cloudflare account ID.
6. Update the `route` field with the route you want to deploy the worker to.
7. Update the `zone_id` field with the zone you want to deploy the worker to.
8. Save the file.

```toml
name = "monocle"
main = "src/index.ts"
compatibility_date = "${TODAYS_DATE}"
compatibility_flags = [ "nodejs_compat" ]
account_id = "${YOUR_ACCOUNT_ID}"
workers_dev = false # Set to false to deploy to custom domain
route = { pattern = "${YOUR_ROUTE}", zone_id = "${YOUR_ZONE}" }
```

**Set up your secrets**

```sh
wrangler secret put PUBLISHABLE_KEY
wrangler secret put SECRET_KEY
# The cookie secret must be 32 bytes "openssl rand -hex 32"
wrangler secret put COOKIE_SECRET_VALUE
```

To use manual decryption set the `PRIVATE_KEY` secret. This is feature is only available to customers with Enterprise plans.

```sh
wrangler secret put PRIVATE_KEY
```

**Opt in to the Policy API**

If you want to use Spur's Policy API for assessment decisions instead of the default local decryption path, set the following secret:

```sh
wrangler secret put USE_POLICY_API   # set value to: true
```

When `USE_POLICY_API=true`:
- The worker calls Spur's Policy API to evaluate each session
- If you have the relevant Policy blocking entitlements and a policy is configured, traffic that fails the policy check will be blocked with a `403` response
- If no policy is configured or the account does not have blocking entitlements, traffic is allowed through automatically

**Deploy the worker**

```sh
wrangler deploy
```

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `PUBLISHABLE_KEY` | Yes | Your Monocle publishable key |
| `SECRET_KEY` | Yes | Your Monocle secret key |
| `COOKIE_SECRET_VALUE` | Yes | 32-byte hex string for cookie signing |
| `PRIVATE_KEY` | No | PEM private key for local decryption (Enterprise only) |
| `USE_POLICY_API` | No | Set to `true` to use the Policy API instead of local decryption |
| `EXEMPTED_SERVICES` | No | JSON array of service names to exempt from blocking (default: `["WARP_VPN","ICLOUD_RELAY_PROXY"]`) |
| `CLOUDFLARE_NO_CODE` | No | Set automatically by the Spur dashboard — do not set manually |
