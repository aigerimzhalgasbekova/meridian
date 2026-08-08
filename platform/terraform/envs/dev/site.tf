# Portfolio site: static Astro build in S3, served by CloudFront under the
# apex domain. Gated on site_certificate_arn because CloudFront requires an
# ISSUED us-east-1 certificate — leave the variable empty until the ACM
# validation CNAME is in DNS and both certs flip to ISSUED, then set it and
# re-apply. Upload is out-of-band: `aws s3 sync site/dist s3://<bucket>`.

locals {
  site_enabled = var.site_certificate_arn != ""
}

resource "aws_s3_bucket" "site" {
  count  = local.site_enabled ? 1 : 0
  bucket = "${local.name}-site-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "site" {
  count                   = local.site_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.site[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "site" {
  count                             = local.site_enabled ? 1 : 0
  name                              = "${local.name}-site"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# The apex is the only host that can assert HSTS for the whole *.<domain>
# family; the four ALB-backed services set their own headers in application
# middleware. idp (idp/internal/server/middleware.go) and console
# (console/internal/server/server.go) set the full set; portal
# (portal/server/src/app.ts) sets everything except CSP, which its SPA bundle
# needs an audit for. bridge (bridge/internal/server/server.go) sets
# Referrer-Policy only: it serves script-free server-rendered templates with no
# authenticated state-changing UI, so framing and sniffing buy an attacker
# nothing there.
resource "aws_cloudfront_response_headers_policy" "site" {
  count = local.site_enabled ? 1 : 0
  name  = "${local.name}-site-security-headers"

  security_headers_config {
    content_security_policy {
      # ponytail: 'unsafe-inline' for script/style is deliberate — Base.astro
      # ships two FOUC-blocking inline scripts and Astro's default
      # inlineStylesheets: "auto" inlines small stylesheets, so hashes would
      # have to be regenerated on every content edit. Upgrade path: emit
      # sha256 hashes from dist/**/*.html in the CI site job once the deploy
      # itself runs from CI. The site takes no user input and has no cookies.
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
      override                = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }
    # No `preload`: preloading is irrevocable for the entire zone, and nothing
    # has been submitted to the preload list.
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      override                   = true
    }
  }
}

resource "aws_cloudfront_distribution" "site" {
  count = local.site_enabled ? 1 : 0

  enabled             = true
  aliases             = [var.domain, "www.${var.domain}"]
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.site[0].bucket_regional_domain_name
    origin_id                = "site-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.site[0].id
  }

  default_cache_behavior {
    target_origin_id       = "site-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    # AWS managed CachingOptimized policy.
    cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.site[0].id

    # Astro emits directory-style routes (/guide/ -> /guide/index.html); the
    # function rewrites those so S3 finds the object.
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.site_index[0].arn
    }
  }

  # Served from site/src/pages/404.astro, which the Astro build emits as
  # dist/404.html (asserted in the `site` CI job).
  custom_error_response {
    error_code         = 403 # S3 returns 403 for missing keys behind OAC
    response_code      = 404
    response_page_path = "/404.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 404
    response_page_path = "/404.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.site_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# Rewrite /path/ and /path to /path/index.html for Astro's static output.
resource "aws_cloudfront_function" "site_index" {
  count   = local.site_enabled ? 1 : 0
  name    = "${local.name}-site-index"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = <<-EOF
    function handler(event) {
      var req = event.request;
      var uri = req.uri;
      if (uri.endsWith('/')) {
        req.uri = uri + 'index.html';
      } else if (!uri.includes('.')) {
        req.uri = uri + '/index.html';
      }
      return req;
    }
  EOF
}

data "aws_iam_policy_document" "site" {
  count = local.site_enabled ? 1 : 0

  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site[0].arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site[0].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  count  = local.site_enabled ? 1 : 0
  bucket = aws_s3_bucket.site[0].id
  policy = data.aws_iam_policy_document.site[0].json
}

output "site_bucket" {
  value = local.site_enabled ? aws_s3_bucket.site[0].bucket : null
}

output "site_cloudfront_domain" {
  description = "CNAME target for the apex/www records."
  value       = local.site_enabled ? aws_cloudfront_distribution.site[0].domain_name : null
}
