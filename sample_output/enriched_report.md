# IOC Enrichment Report

## Summary

Total IOCs analyzed: 18  
Critical: 1  
High: 0  
Medium: 4  
Low: 13  

## Critical IOCs

| IOC            | Type   |   Score | Summary                                                                                                                                                                                                                            |
|----------------|--------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 185.220.101.45 | ip     |      90 | This ip is critical risk. VirusTotal shows 15 malicious detections; AbuseIPDB reports an abuse confidence score of 100. Recommended action: block immediately, search SIEM logs for communication, and investigate affected hosts. |

## Medium IOCs

| IOC                              | Type   |   Score | Summary                                                             |
|----------------------------------|--------|---------|---------------------------------------------------------------------|
| 45.33.32.156                     | ip     |      25 | This ip is medium risk. VirusTotal shows 4 malicious detection(s).  |
| 194.165.16.77                    | ip     |      25 | This ip is medium risk. VirusTotal shows 1 malicious detection(s).  |
| 198.199.94.61                    | ip     |      35 | This ip is medium risk. VirusTotal shows 2 malicious detection(s).  |
| 44d88612fea8a8f36de82e1278abb02f | hash   |      40 | This hash is medium risk. VirusTotal shows 66 malicious detections. |

## Low IOCs

| IOC                                                              | Type    |   Score | Summary                                                      |
|------------------------------------------------------------------|---------|---------|--------------------------------------------------------------|
| 91.92.109.196                                                    | ip      |       0 | No strong malicious indicators found across checked sources. |
| emotet-c2.ru                                                     | domain  |       0 | No strong malicious indicators found across checked sources. |
| trickbot-panel.xyz                                               | domain  |       0 | No strong malicious indicators found across checked sources. |
| cobalt-strike-c2.com                                             | domain  |       0 | No strong malicious indicators found across checked sources. |
| fakeupdate-delivery.net                                          | domain  |       0 | No strong malicious indicators found across checked sources. |
| redline-stealer.top                                              | domain  |       0 | No strong malicious indicators found across checked sources. |
| http://185.220.101.45/malware/emotet.dll                         | url     |       0 | No strong malicious indicators found across checked sources. |
| http://91.92.109.196/payload/agent.exe                           | url     |       0 | No strong malicious indicators found across checked sources. |
| https://fakeupdate-delivery.net/chrome_update.exe                | url     |       0 | No strong malicious indicators found across checked sources. |
| http://cobalt-strike-c2.com/beacon                               | url     |       0 | No strong malicious indicators found across checked sources. |
| 3395856ce81f2b7382dee72602f798b642f14d0                          | unknown |       0 | No strong malicious indicators found across checked sources. |
| 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b | hash    |       0 | No strong malicious indicators found across checked sources. |
| e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | hash    |       0 | No strong malicious indicators found across checked sources. |
