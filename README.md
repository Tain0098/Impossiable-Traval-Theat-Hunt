# Impossible-Traval-Theat-Hunt

Detection and Analysis 
3 User was flag in search after undertaking the Alert Rule (Potential Impossible Travel) 
KQL query 
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look 
let NumberOfDifferentLocationsAllowed = 2;

SigninLogs 
| where TimeGenerated > ago(TimePeriodThreshold) 
| summarize Count = count() by UserPrincipalName, UserId, City = 
tostring(parse_json(LocationDetails).city), State = 
tostring(parse_json(LocationDetails).state), Country = 
tostring(parse_json(LocationDetails).countryOrRegion) 
| project UserPrincipalName, UserId, City, State, Country 
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, 
UserId 
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed

- UserID- a9d78ae0-ab31-48c2-904a-fe98463a0c64 
4 travel 
False Positive 
Travel between Leicester and Greater London typically takes between 1 and 3 hours, 
depending on your choice of transport which is possible travel.

- UserID-c730940a-4601-4efc-bfdc-cda928469e23                
3 travel 
False Positive 
Varkala to Kollam can be done in 30 minutes, but only if you take the train. Which in 
within acceptable rang
 
- UserID-28c5b00b-977c-4cbe-bdb1-f1463670bdf7 
4 travel 
False Positive 
The distance between Baltimore, MD and Springfield, VA is approximately 50–55 miles 
is common travel and possible 

_______ 
Post-Incident Activities 
● Update policies and tools to prevent recurrence. 
○ You could do something like creating a geo-fencing policy within azure that prevents 
logins outside 
________ 
I. Preparation & Detection 
Incident Source: Microsoft Sentinel Analytic Rule (Potential Impossible Travel) 
NIST Category: Adverse Events / Unauthorized Access Attempts 
Detection KQL Logic 
kusto

let TimePeriodThreshold = timespan(7d); 
SigninLogs 
| where TimeGenerated > ago(TimePeriodThreshold) 
| where ResultType == 0 // Filter for successful logins only 
| extend City = tostring(LocationDetails.city),  
State = tostring(LocationDetails.state),  
Country = tostring(LocationDetails.countryOrRegion), 
Coordinates = parse_json(tostring(LocationDetails.geoCoordinates)) 
| summarize  
LocationCount = dcount(City),  
Cities = make_set(City),  
LastLogin = max(TimeGenerated)  
by UserPrincipalName, UserId 
| where LocationCount > 2

Use code with caution.

______

II. Analysis 
NIST recommends verifying the incident's scope and origin. The following three users 
were analyzed for "Impossible Travel" velocity: 
UserID 
Travel Path 
Verdict 
NIST Disposition

User ID - a9d7...0c64 
Travel Path - Leicester ➔ London 
NIST Disposition - False Positive 
Verdict - Valid local commute (~1hr). Likely GeoIP 
noise.

UserID - c730...9e23 
Travel Path - Varkala ➔ Kollam 
NIST Disposition - False Positive 
Verdict - Valid train travel (~30m). Within physical 
limits.

User ID - 28c5...dfb7 
Travel Path - Baltimore ➔ Springfield 
NIST Disposition - False Positive 
Verdict - Regional commute (~2hrs). Common I-95 
traffic.

Technical Conclusion: These events represent benign traffic misidentified by the 
detection logic due to proximity and regional transit. 
______

III. Containment, Eradication, & Recovery 
● Containment: Score = 0. No evidence of account takeover or session hijacking. 
No systems isolated.

● Eradication: No malware or persistence mechanisms found.

● Recovery: No restoration needed. Users maintain existing access. 
Investigation Pivot Points (Verification): 
To confirm zero impact, the following logs were audited:

● AzureActivity: Checked for unauthorized resource deployment. 
● OfficeActivity: Verified no "New Inbox Rule" or "Bulk File Download" events.

● AuditLogs: Confirmed no unauthorized MFA device registrations.

______

IV. Post-Incident Handling (Lessons Learned) 
NIST recommends improving the process to prevent future false positives.

1. Detection Tuning: Update the Sentinel rule to include a geo_distance_2points 
filter.
 
2. Action: Only alert if speed > 500 km/h AND distance > 150 km.
   
3. Watchlists: Add "Regional Commuter" IPs to a Sentinel Watchlist to suppress 
noise for these specific users.
 
4. Policy Update: Recommend Conditional Access with "Sign-in Risk" policies to 
automatically prompt for MFA rather than generating a manual SOC ticket for 
low-distance shifts. 
