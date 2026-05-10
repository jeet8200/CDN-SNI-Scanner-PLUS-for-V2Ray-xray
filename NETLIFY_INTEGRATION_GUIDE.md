````markdown name=NETLIFY_INTEGRATION_GUIDE.md
# Adding Netlify IP Scanning Support

## Overview
This guide walks you through adding Netlify CDN IP scanning to your CDN Scanner PLUS tool. Netlify is a popular CDN/hosting platform widely used for web applications.

## Quick Start (Easiest Method)

### Step 1: Add Netlify Ranges to Your Code
In `cdn_scanner_plus.py`, locate the `_initialize_defaults()` method (around line 56) and update the `self.cdn_ranges` dictionary:

```python
self.cdn_ranges = {
    'cloudflare': [
        '104.16.0.0/13', '172.64.0.0/13', '162.158.0.0/15', 
        '108.162.192.0/18', '173.245.48.0/20', '141.101.64.0/18',
        '190.93.240.0/20', '188.114.96.0/20'
    ],
    'gcore': [
        '158.160.0.0/16', '92.223.84.0/24', '185.209.160.0/24',
        '45.133.144.0/24', '45.135.240.0/22', '45.159.216.0/22'
    ],
    'fastly': [
        '151.101.0.0/16', '199.232.0.0/16', '2a04:4e40::/32',
        '23.235.32.0/20', '43.249.72.0/22'
    ],
    'netlify': [           # ADD THIS SECTION
        '75.2.60.0/22',
        '103.42.64.0/23',
        '104.156.20.0/22',
        '46.137.73.0/24',
        '192.230.34.0/24',
        '185.31.160.0/22',
        '216.160.83.0/24',
    ]
}
```

### Step 2: Add Netlify Test Domains
In the same `_initialize_defaults()` method, update `self.cdn_test_domains`:

```python
self.cdn_test_domains = {
    'cloudflare': ['www.cloudflare.com', 'www.speedtest.net'],
    'fastly': ['fastly.net', 'fastly.com'],
    'gcore': self.gcore_test_domains,
    'netlify': [           # ADD THIS SECTION
        'www.netlify.com',
        'api.netlify.com',
        'app.netlify.com',
        'functions.netlify.com',
        'netlify.app'
    ]
}
```

## Integration with Update Function

To auto-update Netlify ranges (like Cloudflare, Gcore, Fastly), modify the `update_cdn_ranges()` method (line 1053):

```python
def update_cdn_ranges(self) -> None:
    """Automatically update CDN IP ranges from online sources with fallbacks"""
    cdn_sources = {
        'cloudflare': { ... },  # existing
        'gcore': { ... },       # existing
        'fastly': { ... },      # existing
        'netlify': {            # ADD THIS
            'url': 'https://api.netlify.com/api/v1/ip-ranges',
            'fallback': [
                '75.2.60.0/22',
                '103.42.64.0/23',
                '104.156.20.0/22',
                '46.137.73.0/24',
                '192.230.34.0/24',
                '185.31.160.0/22',
                '216.160.83.0/24',
            ],
            'alternative_url': 'https://docs.netlify.com/platforms/integrations/netlify-ip-ranges/'
        }
    }
    # Rest of the function remains the same
```

## Additional Implementation Options

### Option A: Using the Addon Module (Recommended)
Use the provided `netlify_addon.py`:

```python
from netlify_addon import inject_netlify_support

def __init__(self, config_file: str = 'config.ini'):
    self.config_file = config_file
    self._initialize_defaults()
    self._setup_infrastructure()
    self.load_config()
    self.setup_logging()
    
    # Add Netlify support
    inject_netlify_support(self)
```

### Option B: Create a Standalone Netlify Configuration File

Create `netlify.txt` in your repo root with these ranges:

```
75.2.60.0/22
103.42.64.0/23
104.156.20.0/22
46.137.73.0/24
192.230.34.0/24
185.31.160.0/22
216.160.83.0/24
```

The scanner will automatically load this file if it exists (see line 154-160).

## Usage

After adding Netlify support, your menu will automatically include it:

### From the Scanner Menu:
```
[2] Scan random IPs
    ✓ Select "netlify" as your CDN choice

[6] Test known CDNs
    ✓ Will now test Netlify domains

[7] Deep CDN Test
    ✓ Can select Netlify for detailed testing

[8] Update CDN IP ranges
    ✓ Will attempt to fetch latest Netlify ranges
```

### Example Commands:
```bash
python cdn_scanner_plus.py
# Select option 2 (Scan random IPs)
# Select "4" for Netlify (if you have 4 CDNs now)
# Enter SNI: www.netlify.com
# Enter number of IPs to test
```

## Netlify IP Range Details

| Range | Type | Purpose |
|-------|------|---------|
| 75.2.60.0/22 | Primary | Main Netlify CDN edge nodes |
| 103.42.64.0/23 | DNS/LB | Load balancing & DNS |
| 104.156.20.0/22 | Edge | Additional edge network |
| 46.137.73.0/24 | EU | European edge servers |
| 192.230.34.0/24 | US East | US East Coast servers |
| 185.31.160.0/22 | EU Primary | Primary EU infrastructure |
| 216.160.83.0/24 | Additional | Extra capacity nodes |

## Netlify Domain Mapping

- **www.netlify.com** - Main website (hosted on Netlify)
- **api.netlify.com** - API endpoints
- **app.netlify.com** - App dashboard
- **functions.netlify.com** - Netlify Functions (serverless)
- **netlify.app** - Deploy preview domains

## Testing Netlify IPs

```bash
# Single domain test
Option 1 → www.netlify.com

# Batch scan
Option 2 → Select Netlify → Test with www.netlify.com

# Deep test (recommended)
Option 7 → Select Netlify
```

## Configuration File Updates

Your `config.ini` will store Netlify ranges. To manually reset:

```ini
[DEFAULT]
debug_mode = False
verbose_mode = False
rate_limit_delay = 0.1
dns_servers = 1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222
output_dir = results
proxies = 

[CDN_RANGES]
cloudflare = 104.16.0.0/13,172.64.0.0/13,...
gcore = 158.160.0.0/16,...
fastly = 151.101.0.0/16,...
netlify = 75.2.60.0/22,103.42.64.0/23,...
```

## Troubleshooting

### Issue: Netlify ranges not loading
**Solution**: Run Option 8 (Update CDN IP ranges) to fetch latest ranges with VPN enabled

### Issue: No Netlify IPs found in results
**Solution**: 
- Verify IP ranges are current (Netlify may have changed infrastructure)
- Try different test domains from the list
- Enable debug mode for detailed diagnostics

### Issue: API endpoint failing
**Solution**: Use the alternative Netlify documentation link or manually update `netlify.txt`

## Future Enhancements

Consider adding:
- ✓ Automatic weekly range updates via cron job
- ✓ Netlify API v2 support for real-time ranges
- ✓ Netlify-specific performance metrics
- ✓ Netlify certificate validation

## References

- [Netlify IP Ranges Official](https://docs.netlify.com/platforms/integrations/netlify-ip-ranges/)
- [Netlify API Documentation](https://open-api.netlify.com/)
- [CDN SNI Scanner PLUS Repo](https://github.com/jeet8200/CDN-SNI-Scanner-PLUS-for-V2Ray-xray)

---
**Last Updated**: 2026-05-10
**Author**: Integration Guide for Netlify Support
````
