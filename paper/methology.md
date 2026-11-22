## ৩.১ — Network and IoT Environment (টেস্ট করার জায়গা তৈরি)

প্রথমে একটা experimental setup বানাতে হবে — মানে আসল বা simulate করা IoT network, যেখানে কিছু device স্বাভাবিকভাবে কাজ করবে আর কিছু আক্রমণ (attack) করবে। এটা বানানো যায় দুইভাবে:

Simulation software দিয়ে (NS-3, OMNeT++) — কম্পিউটারেই পুরো নেটওয়ার্ক নকল করা
আসল hardware দিয়ে (Raspberry Pi, ESP32) — বাস্তব ছোট device দিয়ে টেস্টবেড বানানো

## ৩.২ — Network Traffic Collection (ডেটা সংগ্রহ)

নেটওয়ার্কে কী হচ্ছে সেটা বুঝতে হলে আগে ডেটা লাগবে। তাই traffic থেকে বিভিন্ন feature সংগ্রহ করা হবে — যেমন কোন device কোথায় data পাঠাচ্ছে, কত দ্রুত পাঠাচ্ছে, কোন protocol/port ব্যবহার করছে ইত্যাদি। এটাই পরে ML model-কে "শেখানোর" জন্য কাজে লাগবে। এখানে existing dataset-ও ব্যবহার হবে (UNSW-NB15, CICIDS2017, N-BaIoT) — এগুলো বিশ্বমানের গবেষণায় ব্যবহৃত standard IoT/network attack dataset।

## ৩.৩ — Data Preprocessing (ডেটা পরিষ্কার করা)

Raw ডেটা সরাসরি ML model-এ দেওয়া যায় না। তাই:

missing/duplicate data ফেলে দেওয়া
normalize করা (সব সংখ্যা একই স্কেলে আনা)
দরকারি feature বেছে নেওয়া (feature selection) — যাতে model দ্রুত ও কার্যকর হয়, বিশেষ করে resource-limited IoT device-এ চালানোর জন্য।

## ৩.৪ — AI-Based Detection (আসল ML/AI অংশ)

এখানে বিভিন্ন Machine Learning মডেল ট্রেনিং হবে normal আর malicious traffic আলাদা করার জন্য। আপনার proposal-এ কয়েকটা model compare করা আছে:

Model সুবিধা অসুবিধা
Random Forest accurate, বোঝা সহজ বড় হলে memory বেশি লাগে
XGBoost fast, ভালো performance tuning কঠিন
Autoencoder নতুন/unseen attack ধরতে পারে threshold ঠিক করা কঠিন
Deep Learning (LSTM) জটিল pattern ধরতে পারে অনেক data ও compute লাগে

Model-এর output হলো: প্রতিটা device/traffic-এর জন্য একটা “threat probability” (কতটা সম্ভাবনা এটা attack)।

## ৩.৫ — Behavioral Threat Analysis (আচরণ বিশ্লেষণ)

শুধু একটা packet দেখে সিদ্ধান্ত না নিয়ে, সময়ের সাথে device-টার সামগ্রিক আচরণ দেখা হবে —

স্বাভাবিক আচরণ → Low risk
একটু অস্বাভাবিক → Medium risk
বারবার খারাপ আচরণ → High risk

## ৩.৬ — Dynamic Trust Management (ট্রাস্ট স্কোর)

এখানে প্রতিটা device-কে একটা trust score (০-১০০) দেওয়া হয়, যেটা নির্ভর করে:

আগের আচরণের ইতিহাসের উপর
ML model-এর threat probability-র উপর
authentication status-এর উপর

এই score সময়ের সাথে বদলাতে থাকে (continuous verification) — এটাই Zero-Trust-এর মূল নীতি। আপনার Figure 2-তে এই score কীভাবে ওঠানামা করে সেটা একটা conceptual গ্রাফে দেখানো আছে (normal device-এর score স্থিতিশীল থাকে, compromised device-এর score ক্রমশ কমে যায়)।

## ৩.৭ — Zero-Trust Enforcement (সিদ্ধান্ত নেওয়া)

Trust score আর behavior অনুযায়ী system স্বয়ংক্রিয়ভাবে ব্যবস্থা নেবে — শুধু network-এর ভিতরে আছে বলেই কাউকে বিশ্বাস করবে না (এটাই “Never trust, always verify” নীতি)।

## ৩.৮ — Security Response Pipeline (পুরো প্রক্রিয়ার ফ্লো)

পুরো জিনিসটা একটা চেইন হিসেবে কাজ করে (Figure 3-এ দেখানো আছে):

Traffic Capture → Feature Extraction → ML Detection → Threat Probability
→ Behavioral Risk Scoring → Trust Score Update → Zero-Trust Decision
→ Action (Allow/Monitor/Restrict/Re-authenticate/Isolate/Block)

## ৩.৯ — Experimental Evaluation (কীভাবে যাচাই করবেন কাজ করছে কিনা)

শেষে system-টা কতটা ভালো কাজ করছে সেটা মাপার জন্য দুই ধরনের metric ব্যবহার হবে:

Security metrics: Accuracy, Precision, Recall, F1-score, False Positive Rate — মানে model কতটা সঠিকভাবে attack ধরতে পারছে
Performance metrics: Latency, CPU/Memory usage — মানে system-টা কতটা fast ও lightweight, IoT device-এ চালানোর উপযোগী কিনা

সংক্ষেপে Methodology-র flow বললে:

Traffic collect করবো → ML দিয়ে চিনবো কোনটা attack → device-এর behavior দেখে trust score দেবো → সেই score অনুযায়ী automatically access control করবো → শেষে accuracy আর speed মেপে দেখাবো system কার্যকর কিনা।
