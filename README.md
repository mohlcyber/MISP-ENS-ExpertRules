# MISP-ENS-ExpertRules

This integration provides the ability to push MISP indicators (hashes) to McAfee ePolicy Orchestrator to create new Expert Rules in an exisiting assigned policy.
Based on this policy McAfee protected endpoints will be able to block file executions based on MISP threat events.

# Proccedure

The script will run every minute - Hash Indicators from Events in MISP that are tagged (with a specific tag) will be extracted and checked agains a cached file if hashes are already part of the ENS Expert Rule. If not it will append the hashes. After, the script will check EPO, if the policy exist already and download the policy. The downloaded policy will be modified with the new hashes and uploaded back to EPO.

<p align="center"><img width="826" alt="Screenshot 2020-08-05 at 16 52 38" src="https://user-images.githubusercontent.com/25227268/89427967-23643200-d73c-11ea-8e81-1075a51d00e0.png"></p>

# Prerequisits

1. Make sure that all python libraries are installed. 

```pip install pymisp```

2. IP, Port, Username and Password for ePolicy Orchestrator. Make sure you have a Policy name and the Signature ID of the expert rule (line 18 - 23).

To retrieve the signature id go to Policy Catalog > Endpoint Security Threat Prevention > Exploit Prevention > Go into the policy > Get the ID for the rule to update.
![Screenshot 2020-08-06 at 14 05 13](https://user-images.githubusercontent.com/25227268/89529946-ebb5c280-d7ed-11ea-9a49-b6422b58016d.png)


!Please make sure to have a dedicated Expert Rule for this integration!

3. IP, API key for MISP (line 25 - 27).

4. MISP Tag that should be used to query MISP Events (line 28).


