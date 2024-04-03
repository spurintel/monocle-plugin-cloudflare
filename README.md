# Monocle by Spur
[![Deploy with Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/spurintel/monocle-plugin-cloudflare/tree/main/)

Easily deploy a CloudFlare service worker with Monocle that will automatically protect your site from residential proxies, malware proxies, or other commerical anonymity services.

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

## Setup

To install this worker from the command line, make sure you have `wrangler` installed globally.

```sh
$ npm install -g wrangler
```

You will need to update the `wrangler.toml` file and set your `account_id` and `route`.

This utility supports both user and Spur managed encryption. If you are creating a new deployment for this project, the user managed encryption is much more performant. You may need to specify which environment these are deployed to with the `--env ENVIRONMENT` options.

If you selected Spur managed encryption, set the following env variables:
```sh
$ wranger secret put VERIFY_TOKEN
$ wranger secret put SITE_TOKEN
# This following command is hopefully only temporary until we come up with a stateful solution. This is similar to what is done in our NGINX version
$ wrangler secret put COOKIE_SECRET_VALUE
```

If you selected User managed encryption, set the following env variables:
```sh
$ wranger secret put PRIVATE_KEY
$ wranger secret put SITE_TOKEN
# This following command is hopefully only temporary until we come up with a stateful solution. This is similar to what is done in our NGINX version
$ wrangler secret put COOKIE_SECRET_VALUE
```


```sh
$ npm run deploy-spur-managed
# or
$ npm run deploy-user-managed
```
