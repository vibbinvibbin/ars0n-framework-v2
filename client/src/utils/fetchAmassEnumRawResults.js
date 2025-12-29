export const fetchAmassEnumRawResults = async (scanId) => {
  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}/amass-enum-company/${scanId}/raw-results`
    );
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const rawResults = await response.json();
    return rawResults || [];
  } catch (error) {
    console.error('[AMASS-ENUM-RAW-RESULTS] Error fetching raw results:', error);
    return [];
  }
}; 