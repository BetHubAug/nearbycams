# Nearby Cams Documentation

## Production Camscan_v2.py Implementation
The `camscan_v2.py` script has been implemented to enhance our capabilities for scanning and finding nearby cameras.

### Environment Variables
Make sure to set the following environment variables for `camscan_v2.py` to function correctly:
- **SHODAN_API_KEY**: Your Shodan API key.
- **CAM_USER**: Username for the camera.
- **CAM_PASS**: Password for the camera.
- **SCAN_NETWORK**: The network range to scan (e.g., 192.168.1.0/24).
- **SEARCH_RADIUS**: Distance in meters to search for nearby cameras.
- **TIMEOUT**: Timeout duration for scanning requests.
- **THREADS**: Number of concurrent threads to use during the scan.
- **OUTPUT_DIR**: Directory where scan results will be saved.

### Usage Instructions
To run the `camscan_v2.py`, use the following command:
```bash
python camscan_v2.py
```
Make sure the environment variables are properly set before executing the script.

### Security Enhancements
We have incorporated several security enhancements in `camscan_v2.py`, including:
- Improved authentication handling.
- Secure storage of sensitive information.
- Rate limiting to prevent abuse of the Shodan API.

### Differences from Original Camscan.py
The `camscan_v2.py` has the following improvements over the original `camscan.py`:
- Enhanced error handling.
- More optimized network scanning methods.
- Expanded support for additional camera protocols and types.

For further information, please refer to the official documentation, or raise issues if you encounter any problems.