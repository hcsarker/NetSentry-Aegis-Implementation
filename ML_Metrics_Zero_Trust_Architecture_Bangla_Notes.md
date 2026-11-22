# Cybersecurity & ML Evaluation Metrics এবং Zero-Trust Architecture

এই নোটে Machine Learning model evaluation-এর ছয়টি metric এবং Network
Security-এর তিনটি গুরুত্বপূর্ণ ধারণা---Zero Trust Architecture (ZTA), NIST
Zero Trust Architecture এবং Castle-and-Moat model---সহজ বাংলায় ব্যাখ্যা
করা হয়েছে।

------------------------------------------------------------------------

## Part 1: Machine Learning Evaluation Metrics

ধরা যাক, একটি cybersecurity system network traffic বিশ্লেষণ করে বলে দেয়
কোন traffic **Normal** এবং কোনটি **Attack**। এখানে Attack-কে Positive
class ধরা হলো।

### 1. Accuracy

**অর্থ:** মোট যতগুলো prediction করা হয়েছে, তার মধ্যে কতগুলো সঠিক হয়েছে।

\[ Accuracy = `\frac{TP+TN}{TP+TN+FP+FN}`{=tex} \]

-   **TP (True Positive):** Attack ছিল, model Attack বলেছে।
-   **TN (True Negative):** Normal ছিল, model Normal বলেছে।
-   **FP (False Positive):** Normal ছিল, কিন্তু model ভুল করে Attack বলেছে।
-   **FN (False Negative):** Attack ছিল, কিন্তু model ভুল করে Normal বলেছে।

**উদাহরণ:** ১০০টি network packet-এর মধ্যে ৯০টি সঠিকভাবে শনাক্ত হলে
Accuracy = ৯০%।

**সীমাবদ্ধতা:** Dataset-এ যদি ৯৯০টি Normal এবং মাত্র ১০টি Attack থাকে,
সবকিছুকে Normal বললেও Accuracy ৯৯% হতে পারে। অথচ model একটিও Attack ধরতে
পারেনি। তাই imbalanced cybersecurity dataset-এ শুধু Accuracy দেখে সিদ্ধান্ত
নেওয়া ঠিক নয়।

### 2. Precision

**অর্থ:** Model যতগুলোকে Attack বলেছে, তার মধ্যে আসলেই কতগুলো Attack ছিল?

\[ Precision = `\frac{TP}{TP+FP}`{=tex} \]

**উদাহরণ:** Model ২০টি traffic-কে Attack বলেছে; এর মধ্যে ১৬টি সত্যিই
Attack। Precision = ১৬/২০ = ৮০%।

**কেন দরকার:** False Alarm বা অপ্রয়োজনীয় alert কমাতে সাহায্য করে।
Precision বেশি হলে model-এর Attack alert-গুলোর ওপর বেশি আস্থা রাখা যায়।

### 3. Recall (Detection Rate / Sensitivity)

**অর্থ:** বাস্তবে যতগুলো Attack ছিল, model তার মধ্যে কতগুলো ধরতে পেরেছে?

\[ Recall = `\frac{TP}{TP+FN}`{=tex} \]

**উদাহরণ:** বাস্তবে ২৫টি Attack ছিল, model ২০টি ধরেছে। Recall = ২০/২৫ =
৮০%।

**কেন দরকার:** Security system-এ Attack মিস করা বিপজ্জনক। তাই intrusion
detection বা threat detection-এ Recall অনেক গুরুত্বপূর্ণ।

### 4. F1-Score

**অর্থ:** Precision এবং Recall-এর harmonic mean। দুটির মধ্যে ভারসাম্য বোঝায়।

\[ F1 = 2
`\times `{=tex}`\frac{Precision \times Recall}{Precision+Recall}`{=tex}
\]

**উদাহরণ:** Precision = ০.৮০ এবং Recall = ০.৬০ হলে:

\[ F1 = 2 `\times `{=tex}`\frac{0.80 \times 0.60}{0.80+0.60}`{=tex}
`\approx 0.686`{=tex} \]

**কেন দরকার:** Precision ও Recall দুটিই গুরুত্বপূর্ণ হলে F1 ব্যবহার করা হয়। তবে
কোনটি বেশি জরুরি, সেটি application অনুযায়ী ঠিক করতে হবে।

### 5. ROC-AUC

**ROC (Receiver Operating Characteristic) curve** বিভিন্ন classification
threshold-এ:

-   **TPR / Recall:** (TP/(TP+FN))
-   **FPR:** (FP/(FP+TN))

এর সম্পর্ক দেখায়।

**AUC (Area Under the Curve)** হলো ROC curve-এর নিচের ক্ষেত্রফল। এটি model
positive ও negative sample-কে আলাদা করতে কতটা সক্ষম, তার একটি
threshold-independent ধারণা দেয়।

সাধারণ ব্যাখ্যা:

       ROC-AUC সাধারণ ব্যাখ্যা
  ------------ ------------------------
          0.50 Random guessing-এর মতো
    0.60--0.70 দুর্বল discrimination
    0.70--0.80 মোটামুটি
    0.80--0.90 ভালো
    0.90--1.00 খুব ভালো

এগুলো আনুমানিক ব্যাখ্যা, সর্বজনীন মানদণ্ড নয়। Imbalanced dataset-এ ROC-AUC
ভালো দেখালেও positive class-এর precision খারাপ হতে পারে। সে ক্ষেত্রে
PR-AUC-ও দেখা উপকারী।

### 6. Latency (ms)

**অর্থ:** একটি request, packet বা input বিশ্লেষণ করে model/system-এর
response দিতে যত সময় লাগে। এখানে ms মানে millisecond; ১ সেকেন্ড = ১০০০
ms।

**উদাহরণ:** একটি network flow model-এ পাঠানোর পর ফল পেতে ২৫ ms লাগলে
latency = ২৫ ms।

**কেন দরকার:** Real-time intrusion detection বা Zero-Trust access
decision-এ দ্রুত সিদ্ধান্ত প্রয়োজন। Latency কম হওয়া ভালো, তবে measurement-এ
কোন অংশ অন্তর্ভুক্ত---শুধু model inference, নাকি preprocessing, network
communication ও policy enforcement-সহ পুরো pipeline---তা স্পষ্ট করতে হবে।

### Metrics একসাথে কীভাবে বুঝবে?

  Metric      মূল প্রশ্ন                               সাধারণত কোন সমস্যা বোঝায়
  ----------- ------------------------------------- -------------------------
  Accuracy    মোট prediction-এর কতটি ঠিক?           Overall correctness
  Precision   Attack alert-এর কতটি সত্যি?            False alarm
  Recall      আসল Attack-এর কতটি ধরা পড়েছে?         Missed attack
  F1-Score    Precision ও Recall-এর ভারসাম্য কেমন?   Balanced detection
  ROC-AUC     Class আলাদা করার ক্ষমতা কেমন?          Ranking/discrimination
  Latency     সিদ্ধান্ত দিতে কত সময় লাগে?             Response speed

**মনে রাখবে:** Security model-এর জন্য Recall বেশি গুরুত্বপূর্ণ হতে পারে, কারণ
Attack মিস করা ঝুঁকিপূর্ণ। কিন্তু Precision-ও দরকার, কারণ অতিরিক্ত false alarm
security team-কে alert fatigue-তে ফেলতে পারে। তাই metric বাছাই করতে হবে
system-এর লক্ষ্য অনুযায়ী।

------------------------------------------------------------------------

## Part 2: Zero Trust Architecture (ZTA)

### 1. Zero Trust কী?

**Zero Trust** হলো cybersecurity-এর একটি security approach বা
architecture যেখানে কোনো user, device, application বা network
connection-কে শুধু network-এর ভেতরে আছে বলে বিশ্বাস করা হয় না।

সহজ ভাষায়:

> "Never trust, always verify" --- কাউকে বা কোনো device-কে স্বয়ংক্রিয়ভাবে
> trusted ধরে নেওয়া যাবে না; access দেওয়ার আগে পরিচয়, device condition,
> context এবং policy যাচাই করতে হবে।

এটি একটি slogan-ভিত্তিক ধারণা নয়; বাস্তবে identity, device, policy,
authentication, authorization, monitoring এবং least-privilege access
একসাথে কাজ করে।

### 2. Zero Trust-এর মূল নীতিগুলো

1.  **Verify explicitly:** User identity, device, location/context,
    resource এবং risk signal বিবেচনা করে access যাচাই।
2.  **Least-privilege access:** কাজের জন্য যতটুকু permission দরকার, শুধু
    ততটুকুই দেওয়া।
3.  **Assume breach:** System ইতোমধ্যে compromise হতে পারে---এমন ধারণা
    রেখে design করা; segmentation, monitoring এবং দ্রুত response রাখা।
4.  **Continuous evaluation:** Access একবার দিলেই চিরস্থায়ী বিশ্বাস নয়;
    session ও risk পরিবর্তন হলে পুনরায় যাচাই বা access সীমিত করা।
5.  **Resource-focused security:** শুধু network perimeter নয়, প্রতিটি
    গুরুত্বপূর্ণ resource-কে সুরক্ষিত করা।

### 3. একটি সহজ উদাহরণ

ধরা যাক, একজন employee অফিসের Wi-Fi থেকে company database access করতে
চায়।

পুরোনো পদ্ধতিতে অফিসের network-এ ঢুকতে পারলেই তাকে অনেক resource access
করতে দেওয়া হতে পারে।

Zero Trust পদ্ধতিতে system যাচাই করবে:

-   Employee-এর পরিচয় সঠিক কি না?
-   MFA (Multi-Factor Authentication) সম্পন্ন হয়েছে কি না?
-   Device অনুমোদিত ও নিরাপদ কি না?
-   Employee-এর ওই database access করার প্রয়োজনীয় permission আছে কি না?
-   Login/session-এর আচরণ বা context ঝুঁকিপূর্ণ কি না?

সব policy check পাস করলে প্রয়োজনীয় সীমিত access দেওয়া হবে। Risk বাড়লে
access block, limit বা re-authentication চাওয়া হতে পারে।

------------------------------------------------------------------------

## Part 3: NIST Zero Trust Architecture

### 1. NIST কী?

**NIST**-এর পূর্ণরূপ National Institute of Standards and Technology। এটি
যুক্তরাষ্ট্রের একটি standards and technology organization। NIST Special
Publication 800-207-এ Zero Trust Architecture-এর একটি widely used
reference model প্রকাশ করেছে।

NIST ZTA কোনো নির্দিষ্ট vendor-এর product নয়। এটি Zero Trust system কীভাবে
design ও operate করা যায়, তার architecture model এবং terminology দেয়।

### 2. NIST ZTA-এর প্রধান logical components

**Policy Engine (PE):** Access request-এর বিষয়ে সিদ্ধান্ত নেয়---অনুমতি
দেওয়া হবে, নাকি deny করা হবে। Policy এবং বিভিন্ন তথ্যের ভিত্তিতে সিদ্ধান্ত
তৈরি করে।

**Policy Administrator (PA):** Policy Engine-এর সিদ্ধান্ত বাস্তবায়নের জন্য
access session তৈরি, পরিচালনা বা বন্ধ করার কাজ করে।

**Policy Enforcement Point (PEP):** User/device এবং protected
resource-এর মাঝখানে enforcement point হিসেবে কাজ করে। এটি access request
forward করে এবং অনুমোদিত/নিষিদ্ধ access কার্যকর করে।

**Policy Decision Point (PDP):** NIST model-এ Policy Engine ও Policy
Administrator মিলে PDP-এর ভূমিকা পালন করে।

**Data Sources:** Identity management, device management, threat
intelligence, security analytics, logs এবং অন্যান্য context source থেকে
তথ্য আসে। এসব তথ্য policy decision-কে সাহায্য করে।

### 3. NIST ZTA-এর simplified workflow

``` text
User / Device
     |
     v
Access Request
     |
     v
Policy Enforcement Point (PEP)
     |
     v
Policy Decision Point (PDP)
     |
     +-----------------------------+
     |                             |
     v                             v
Policy Engine (PE)          Context / Data Sources
     |                      - Identity information
     |                      - Device health
     |                      - Threat intelligence
     |                      - Security logs
     |                             |
     +----------- evaluate <------+
     |
     v
Policy Administrator (PA)
     |
     v
PEP applies the decision
     |
     +---- Allow limited access ----> Protected Resource
     |
     +---- Deny / revoke access
```

এটি বোঝার সুবিধার জন্য simplified diagram। বাস্তব deployment-এ
component-গুলোর implementation এবং communication ভিন্ন হতে পারে।

### 4. একটি practical scenario

1.  User একটি application খুলে sensitive database access চায়।
2.  PEP request-টি intercept করে।
3.  PDP-এর Policy Engine identity, device health, permissions ও risk
    context evaluate করে।
4.  Policy অনুযায়ী access অনুমোদিত হলে Policy Administrator প্রয়োজনীয়
    session/configuration কার্যকর করতে সাহায্য করে।
5.  PEP শুধু অনুমোদিত resource-এ সীমিত access দেয়।
6.  Session চলাকালে risk signal বদলালে policy পুনর্মূল্যায়ন করে access সীমিত
    বা revoke করা হতে পারে।

------------------------------------------------------------------------

## Part 4: Castle-and-Moat Architecture

### 1. Castle-and-Moat কী?

এটি traditional perimeter-based network security model। এখানে
organization-এর internal network-কে একটি দুর্গ (Castle) এবং
firewall/perimeter-কে দুর্গের চারপাশের পরিখা (Moat)-এর মতো ভাবা হয়।

-   Firewall ও perimeter security দিয়ে বাইরের network traffic নিয়ন্ত্রণ
    করা হয়।
-   Internal network-কে তুলনামূলকভাবে trusted ধরে নেওয়া হয়।
-   একবার ভেতরে ঢুকতে পারলে অনেক ক্ষেত্রে internal resource-এ access পাওয়া
    সহজ হতে পারে।

### 2. উদাহরণ

একটি university network-এ firewall আছে। বাইরের attacker-কে firewall আটকে
দেয়। কিন্তু কোনো attacker phishing-এর মাধ্যমে একজন employee-এর account পেয়ে
internal network-এ ঢুকে গেলে, network segmentation ও internal access
control দুর্বল হলে সে অন্য server-এও যাওয়ার চেষ্টা করতে পারে।

এটিই perimeter security-এর একটি গুরুত্বপূর্ণ সীমাবদ্ধতা: perimeter অতিক্রম করার
পর internal threat যথেষ্টভাবে নিয়ন্ত্রণ না-ও হতে পারে।

### 3. Castle-and-Moat-এর সীমাবদ্ধতা

-   Insider threat মোকাবিলা দুর্বল হতে পারে।
-   Stolen credentials দিয়ে internal access অপব্যবহার হতে পারে।
-   Remote work, cloud services ও mobile devices-এর যুগে একটি নির্দিষ্ট
    perimeter ধরে রাখা কঠিন।
-   Internal lateral movement-এর ঝুঁকি থাকে।
-   Network-এর ভেতরে থাকা মানেই user/device নিরাপদ---এমন নয়।

Castle-and-Moat মানেই firewall অপ্রয়োজনীয় নয়। Firewall এখনও গুরুত্বপূর্ণ; তবে
একে একমাত্র security boundary হিসেবে নির্ভর করা যথেষ্ট নয়।

------------------------------------------------------------------------

## Part 5: Castle-and-Moat বনাম Zero Trust

  -----------------------------------------------------------------------
  বিষয়                    Castle-and-Moat         Zero Trust
  ----------------------- ----------------------- -----------------------
  মূল ধারণা                Network perimeter রক্ষা  প্রতিটি access request
                                                  যাচাই

  Internal network        তুলনামূলক trusted         স্বয়ংক্রিয়ভাবে trusted নয়

  Access                  Perimeter পার হলে       Identity, device,
                          access তুলনামূলক সহজ হতে  context ও policy অনুযায়ী
                          পারে                    

  Trust                   Network location-এ বেশি Explicit verification ও
                          নির্ভরতা                 least privilege

  Monitoring              Perimeter-কেন্দ্রিক হতে   Resource ও
                          পারে                    session-কেন্দ্রিক
                                                  continuous evaluation

  Remote/cloud            পরিচালনা কঠিন হতে পারে  Distributed
  environment                                     environment-এর জন্য বেশি
                                                  উপযোগী

  Internal attacker       Lateral movement-এর ঝুঁকি Segmentation ও
                                                  restricted access দিয়ে
                                                  ঝুঁকি কমানো যায়
  -----------------------------------------------------------------------

**সহজভাবে:** Castle-and-Moat বলে, "দুর্গের ভেতরে ঢুকতে পারলে তুমি তুলনামূলক
নিরাপদ।" Zero Trust বলে, "ভেতরে থাকলেও প্রতিটি resource access করার সময়
যাচাই হবে।"

------------------------------------------------------------------------

## Part 6: Thesis / Research-এ এগুলো কীভাবে ব্যবহার করবে?

ধরা যাক, তুমি একটি AI-driven network intrusion detection এবং Zero-Trust
access control system তৈরি করছ।

একটি সম্ভাব্য workflow:

1.  Network traffic বা flow data সংগ্রহ।
2.  Data preprocessing ও feature extraction।
3.  ML model দিয়ে malicious traffic বা suspicious behavior শনাক্ত।
4.  Model-এর performance Accuracy, Precision, Recall, F1-score ও ROC-AUC
    দিয়ে মূল্যায়ন।
5.  Policy Engine ML risk score-সহ identity, device health ও access
    policy বিবেচনা করে access decision নিতে পারে।
6.  PEP policy অনুযায়ী access allow, deny বা revoke করে।
7.  পুরো pipeline-এর latency ms-এ মাপা।
8.  Baseline হিসেবে traditional Castle-and-Moat approach-এর সঙ্গে তুলনা
    করা যেতে পারে।

### Research evaluation-এর সতর্কতা

-   ML detection performance এবং Zero-Trust access-control effectiveness
    এক জিনিস নয়; আলাদা করে evaluate করা উচিত।
-   Model-এর Accuracy/F1 ভালো হলেই architecture নিরাপদ প্রমাণ হয় না।
-   Latency কোথা থেকে কোথা পর্যন্ত মাপা হয়েছে, তা methodology-তে লিখতে
    হবে।
-   False Positive, False Negative, throughput, resource overhead এবং
    access-decision time-ও প্রাসঙ্গিক হতে পারে।
-   Baseline comparison করতে হলে একই dataset, traffic condition,
    hardware এবং measurement procedure যতটা সম্ভব consistent রাখতে হবে।

------------------------------------------------------------------------

## Quick Revision: এক নজরে

-   **Accuracy:** মোট prediction-এর কত অংশ সঠিক।
-   **Precision:** Attack বলা prediction-এর কত অংশ সত্যিকারের Attack।
-   **Recall:** মোট Attack-এর কত অংশ model ধরেছে।
-   **F1-score:** Precision ও Recall-এর harmonic mean।
-   **ROC-AUC:** Positive ও negative class আলাদা করার ক্ষমতার
    threshold-independent মাপ।
-   **Latency:** response দিতে লাগা সময়।
-   **Zero Trust:** কোনো user/device/resource-কে শুধু location বা network
    membership-এর কারণে trusted ধরা হয় না।
-   **NIST ZTA:** Zero Trust architecture design করার reference model;
    PE, PA ও PEP গুরুত্বপূর্ণ component।
-   **Castle-and-Moat:** Traditional perimeter-based security model;
    বাইরের boundary-তে বেশি নির্ভর করে।

## References

1.  Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero
    Trust Architecture*. NIST Special Publication 800-207.
    https://doi.org/10.6028/NIST.SP.800-207
2.  NIST Computer Security Resource Center. *Zero Trust Architecture
    (ZTA)*. https://csrc.nist.gov/pubs/sp/800/207/final
3.  Fawcett, T. (2006). An introduction to ROC analysis. *Pattern
    Recognition Letters, 27*(8), 861--874.
    https://doi.org/10.1016/j.patrec.2005.10.010
4.  Saito, T., & Rehmsmeier, M. (2015). The precision-recall plot is
    more informative than the ROC plot when evaluating binary
    classifiers on imbalanced datasets. *PLOS ONE, 10*(3), e0118432.
    https://doi.org/10.1371/journal.pone.0118432
