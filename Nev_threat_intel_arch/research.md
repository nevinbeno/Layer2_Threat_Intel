# Layer 2: Research

## 1️⃣ What is Threat Intelligence (Research Perspective)
In simple terms, Threat Intelligence is a mapping <br>**from**: *what we got / what we are* <br>**to**: *what we already know / what we have*.

Layer 1 does the scanning, and gives its output to layer 2. The scanned result contain certain configurations of the device which was subjected to scan. <br>
Layer 2 analyses the scanned result to  find whether the existing configurations are safe, or is there some potential loop holes for any unauthorised penetration. 
<br>
> Real world analogy: Medical Check-up
> - A patient who is going to take a medical checkup <=> Device to be scanned
> - Conduction of medical checkup with sophiscated tools <=> Scanning of that device
> - Test result <=> Layer 1 result
> - Test result being analysed by the Doctor <=> Layer 1 result being fed as input of Layer 2 for Threat Intelligence
> - Doctor understands & explains the issues to the patient <=> Layer 2 output of the detailed Threat Intelligence. 

## 2️⃣ Purpose of Threat Intelligence Layer
# Layer 2: Research

## 1️⃣ What is Threat Intelligence (Research Perspective)
In simple terms, Threat Intelligence is a mapping <br>**from**: *what we got / what we are* <br>**to**: *what we already know / what we have*.

Layer 1 does the scanning, and gives its output to layer 2. The scanned result contain certain configurations of the device which was subjected to scan. <br>
Layer-2 analyzes the scan results to assess whether the discovered configurations introduce security risks or potential attack vectors.
<br>

## 2️⃣ Purpose of Threat Intelligence Layer
Modern vulnerability scanners generate a large volume of raw findings. However, without contextual intelligence—such as exploit availability, known active exploitation, threat reputation, or severity trends—security teams face difficulty in risk prioritization. As a result, all vulnerabilities often appear equally critical, which is not practical in real-world environments.

This research focuses on designing a Threat Intelligence Layer (Layer-2) that:
- Enriches discovered assets with external intelligence sources. 
- Correlates vulnerabilities with real-world threat data. 
- Converts raw scan outputs into actionable security insights. <br>

Hence, Layer-2 acts as the decision-making brain of the security architecture.

## Implementation of the "Brain"
