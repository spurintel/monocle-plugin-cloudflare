# Monocle by Spur

Easily deploy a CloudFlare service worker with Monocle that will automatically protect your site from residential proxies, malware proxies, or other commercial anonymity services.

## Description

Monocle can detect a user session coming from a residential proxy, malware proxy, or other endpoint based proxy network. By detecting this at the session level, you can take action on abusive users without impacting legitimate ones.

[Monocle](https://spur.us/monocle)
[Docs](https://docs.spur.us/#/monocle)
[FAQ](https://spur.us/monocle/#faqs)
[Demo](https://spur.us/app/demos/monocle/form)
[Blog](https://spur.us/announcing-monocle-community-edition)

This CloudFlare service worker will automatically force a Monocle render on new users before allowing them access to your site. Authentic users will not be negatively impacted. The cookie that this plugin sets for the user is good for an hour or whenever the user changes IP addresses.

## Help and Support

support@spur.us

## Terraform

Use our official [Terraform module](https://registry.terraform.io/modules/spurintel/worker-spur-monocle/cloudflare/latest) to quickly integrate the Monocle Cloudflare worker into your Terraform-enabled project.

## Wrangler Setup

### Install Wrangler CLI

Wrangler is the Cloudflare CLI tool that allows you to manage your Cloudflare Workers.
In order to install the Monocle worker make sure you have `wrangler` installed globally.

```sh
npm install -g wrangler
```

Make sure you are logged in to your Cloudflare account with Wrangler.

```sh
wrangler login
```

### Fork this repository

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

### Configure the worker

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
main = "index-spur-managed.js"
compatibility_date = "${TODAYS_DATE}"
compatibility_flags = [ "nodejs_compat" ]
account_id = "${YOUR_ACCOUNT_ID}"
workers_dev = false # Set to false to deploy to custom domain
route = { pattern = "${YOUR_ROUTE}", zone_id = "${YOUR_ZONE}" }
```

### Set up your secrets

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

### Deploy the worker

```sh
 wrangler deploy
```
