import { debugTrace } from './wildcardAutoScan';

export default async function initiateTHCSubdomainScan({
  activeTarget,
  setIsTHCSubdomainScanning,
  setMostRecentTHCSubdomainScan,
  setMostRecentTHCSubdomainScanStatus,
  autoScanSessionId = null
}) {
  setIsTHCSubdomainScanning(true);

  try {
    debugTrace("Initiating THC Subdomain scan directly via API...");

    // 1. Start the scan
    const domain = activeTarget.scope_target.replace('*.', '');
    const requestBody = {
      fqdn: domain
    };
    
    if (autoScanSessionId) {
      requestBody.auto_scan_session_id = autoScanSessionId;
    }

    const scanResponse = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}/thc-subdomain/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      }
    );

    if (!scanResponse.ok) {
      throw new Error(`Failed to start THC Subdomain scan: ${scanResponse.status} ${scanResponse.statusText}`);
    }

    const scanData = await scanResponse.json();
    debugTrace(`Scan initiated with ID: ${scanData.scan_id}`);

    // Create a placeholder scan object to update UI immediately
    const placeholderScan = {
      scan_id: scanData.scan_id,
      status: 'pending',
      created_at: new Date().toISOString()
    };
    setMostRecentTHCSubdomainScan(placeholderScan);
    setMostRecentTHCSubdomainScanStatus('pending');

    // 2. Poll for completion using the scan_id
    let isComplete = false;
    let attempts = 0;
    const maxAttempts = 60; // 5 minute timeout (60 x 5 seconds)

    while (!isComplete && attempts < maxAttempts) {
      attempts++;
      debugTrace(`Polling attempt ${attempts}/${maxAttempts}`);
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds

      const statusResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}/thc-subdomain/${scanData.scan_id}`
      );

      if (!statusResponse.ok) {
        debugTrace(`Failed to fetch scan status: ${statusResponse.status} ${statusResponse.statusText}`);
        continue; // Try again
      }

      const scan = await statusResponse.json();

      if (!scan) {
        debugTrace("No scan found, will try again");
        continue;
      }

      debugTrace(`Retrieved scan: ${JSON.stringify(scan)}`);
      setMostRecentTHCSubdomainScan(scan);
      setMostRecentTHCSubdomainScanStatus(scan.status);
      debugTrace(`Scan status: ${scan.status}`);

      if (scan.status === 'completed' || scan.status === 'success' || scan.status === 'error' || scan.status === 'failed') {
        isComplete = true;
        setIsTHCSubdomainScanning(false);
        debugTrace(`Scan completed with status: ${scan.status}`);
      }
    }

    if (!isComplete) {
      debugTrace("THC Subdomain scan timed out, moving to next step anyway");
    }

    setIsTHCSubdomainScanning(false);

    return { success: true };
  } catch (error) {
    debugTrace(`Error with THC Subdomain scan: ${error.message}`);
    setIsTHCSubdomainScanning(false);
    return { success: false, error: error.message };
  }
}
