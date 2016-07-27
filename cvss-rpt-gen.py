import sys
import csv
import os

import bisect
import argparse
import subprocess
import logging

from decimal import Decimal as D, ROUND_CEILING
from wscoverity import WebServiceClient, ConfigServiceClient, DefectServiceClient

# ---------------------Global Variables------------------------
cvssVersion = 'CVSS:3.0'
cvssScopeCoefficient = D('1.08')
cvssExploitabilityCoefficient = D('8.22')

cvssReport = True
cvssScoring = True

CVSS_AV_vector = ['Network', 'Adjacent', 'Local', 'Physical']
CVSS_AC_vector = ['Low', 'High']
CVSS_PR_vector = ['None', 'Low', 'High']
CVSS_UI_vector = ['None', 'Required']
cvssPrpVector = { 'AV':'N', 'AC':'L', 'PR':'L', 'UI':'N'}
vectorFlag = {'AV':False, 'AC':False, 'PR':False, 'UI':False, 'S':False, 'C':False, 'I':False, 'A':False}
cvssMetrics = ['CVSS_Score', 'CVSS_Severity', 'CVSS_Vector', 'CVSS_Audited']

cvssWeight = {
    'AV': {'N': D('0.85'), 'A': D('0.62'), 'L': D('0.55'), 'P': D('0.2')},
    'AC': {'H': D('0.44'), 'L': D('0.77')},
    'PR':{'N': D('0.85'), 'L': D('0.62'), 'H': D('0.27')},        #These values are used if Scope is Unchanged 
    'PRC':{'N': D('0.85'), 'L': D('0.68'), 'H': D('0.5')},        #These values are used if Scope is Changed PR + C
    'UI': {'N': D('0.85'), 'R': D('0.62')},
    'S':{'U': D('6.42'), 'C': D('7.52')},                          #Note: not defined as constants in specification
    'C':{'N': D('0'),'L': D('0.22'), 'H': D('0.56')},
    'I':{'N': D('0'),'L': D('0.22'), 'H': D('0.56')},
    'A':{'N': D('0'),'L': D('0.22'), 'H': D('0.56')}               #C, I and A have the same weights
    #E: {'X': 1,'U': D('0.91, 'P': D('0.94, 'F': D('0.97, 'H':1},
    #RL:{'X': 1,'O': D('0.95, 'T': D('0.96, 'W': D('0.97, 'U':1},
    #RC:{'X': 1,'U': D('0.92, 'R': D('0.96, 'C': 1},
    #CIAR: {'X': 1, 'L': D('0.5, 'M': 1, 'H': 1.5}                   # CR, IR and AR have the same weights
    #'CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N'
}

cvssMandatory = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
cvssParams = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA']

severityRatings = [ (0.0, 'None'),  (3.9, 'Low' ), (6.9, 'Medium'), (8.9, "High"), (10.0 ,"Critical")]

#----------------------Modules-For-CVSS-Metrics-Calculation---------------------------------------------
def get_severity(score):
    severityRatings.sort() 
    keys = [k[0] for k in severityRatings]
    idx = bisect.bisect_right(keys, score)
    return severityRatings[idx][1]    


def round_up(value):
    """
    Round up is defined as the smallest number, specified to one decimal place, that is equal to
    or higher than its input. For example, Round up (4.02) is 4.1; and Round up (4.00) is 4.0.
    """
    return (value * D('10.0')).to_integral_exact(rounding=ROUND_CEILING) / D('10.0')    
    
def get_baseScore(cvssBStr):
    cvssPairs = cvssBStr.split('/')
    cvssPairs.remove(cvssVersion)
    #cvssPairs.sort()
    cvssPairs.reverse()
    #print (cvssPairs)

    cvssScopeChanged = False
    cvssExploitabalitySubScore = cvssExploitabilityCoefficient
    cvssImpactSubScoreMultiplier = 1
    count = 0
    cvssKeys = []
    for cvssPair in cvssPairs:
        (cvssKey, cvssVal) = cvssPair.split(':')
        cvssKeys.append(cvssKey)
        if (cvssKey == 'S'):
            if (cvssVal == 'C'):
                cvssScopeChanged = True
            try:
                cvssImpactSubScore = cvssWeight[cvssKey][cvssVal]
            except:
                print('CVSS Vector String is Incorrect')
                return -1 
            
        if ((cvssScopeChanged) and cvssKey == 'PR'):
                cvssKey = 'PRC'
            
        if (cvssKey in ['AV', 'AC', 'PR', 'PRC', 'UI']):
            try:
                cvssExploitabalitySubScore *= cvssWeight[cvssKey][cvssVal]
            except:
                print('CVSS Vector String is Incorrect')
                return -1             
            #print ('cvssExploitabalitySubScore:' + str(cvssExploitabalitySubScore))
           
        if (cvssKey in ['C', 'I', 'A']):
            try:
                cvssImpactSubScoreMultiplier *= (1-cvssWeight[cvssKey][cvssVal])
                #print ('cvssImpactSubScoreMultiplier:' + str(cvssImpactSubScoreMultiplier))
            except:
                print('CVSS Vector String is Incorrect')
                return -1 
                
        if (cvssKey in ['E', 'RL', 'RC', 'CR', 'IR', 'Ar', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA']):
            if (count == 0):
                print('Warning: Only manadatory parameters {} in base vector utilized for CVSS base score calculation'.format(cvssMandatory))
                count += 1 
            pass
      
    if not (set(cvssKeys).issubset(set(cvssParams))):
        #print('CVSS Keys:{} \nCVSS Parameters:{}'.format(set(cvssKeys), set(cvssParams)))
        print ("Error: Invalid  Base Vector String detected")
        return -1 
    
    if not set(cvssMandatory).issubset(set(cvssKeys)):
        print('CVSS Mandatory:{} \nCVSS Keys:{}'.format(set(cvssMandatory), set(cvssKeys)))
        print('CVSS Vector String does not contain Mandatory input values')
        return -1      
        
    cvssImpactSubScoreMultiplier = (1-cvssImpactSubScoreMultiplier)
    #print ('cvssImpactSubScoreMultiplier:' + str(cvssImpactSubScoreMultiplier))
    #print ('cvssImpactSubScoreMultiplier:' + str(cvssImpactSubScoreMultiplier))
    if (cvssScopeChanged):
        cvssImpactSubScore *=  ((cvssImpactSubScoreMultiplier - D('0.029')) - D('3.25') * (cvssImpactSubScoreMultiplier - D('0.02'))** D('15'));
    else:
        cvssImpactSubScore *= cvssImpactSubScoreMultiplier;
        
    if (cvssImpactSubScore <= D('0.0')): 
        baseScore = D('0.0');
    else: 
        if (cvssScopeChanged):
            baseScore = round_up(min((cvssExploitabalitySubScore + cvssImpactSubScore) * cvssScopeCoefficient, 10));
        else:
            baseScore = round_up(min((cvssExploitabalitySubScore + cvssImpactSubScore), 10));
    return baseScore

#-----------------------Config-File-Parser------------------------------------------
class ConfigParseProperties:
    def __init__(self, filepath):
        configVal = {}
        with open(filepath) as configFile:
            for line in configFile:
                if line.startswith("#"):
                    continue
                (name, value) = line.partition("=")[::2]
                #print (name, value)
                if (name == 'CVSS_AV_vector'):
                    if value.strip() in CVSS_AV_vector:
                        cvssPrpVector['AV'] = value[0].upper()
                        vectorFlag['AV']  = True
                    else:
                        print ("CVSS_AV_vector value is invalid. Please correct")
                        sys.exit(-1)                   
                elif (name == 'CVSS_AC_vector'):
                    if value.strip() in CVSS_AC_vector:
                        cvssPrpVector['AC'] = value[0].upper()
                        vectorFlag['AC'] = True
                    else:
                        print ("CVSS_AC_vector value is invalid. Please correct")
                        sys.exit(-1)
                elif (name == 'CVSS_PR_vector'):
                    if value.strip() in CVSS_PR_vector:
                        cvssPrpVector['PR'] = value[0].upper()
                        vectorFlag['PR'] = True
                    else:
                        print ("CVSS_PC_vector value is invalid. Please correct")
                        sys.exit(-1)
                elif (name == 'CVSS_UI_vector'):
                    if value.strip() in CVSS_UI_vector:
                        cvssPrpVector['UI'] = value[0].upper()
                        vectorFlag['UI'] = True
                    else:
                        print ("CVSS_UI_vector value is invalid. Please correct")
                        sys.exit(-1)   
                else:
                    configVal[name.strip()] = value.strip()        
            
        #for k,v in configVal.items():
           # print(k, v) 
        self.connectHost = configVal['host']
        self.connectPort = configVal['port']
        sslText = 'false' #configVal['ssl']
        self.connectSsl = sslText.lower() == 'true'        
        self.connectUser = configVal['user']
        self.connectPass = configVal['password']

# --------------------------------Main-Program-----------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Assign CVSS score to defects and generate a report")
    parser.add_argument('--no-report', dest='noreport', action='store_true', help="Generate new CVSS metrics/scores without a report");
    parser.add_argument('--no-scores', dest='noscore', action='store_true', help="Generate a report without updating CVSS metrics");
    parser.add_argument('--log-file', dest='logfile',  help="Generate a log file");
    parser.add_argument('--output', dest='filename',  help="Specify a name for the pdf report");


    group1 = parser.add_argument_group('required arguments')
    group1.add_argument('--project', dest='project', required=True, help="Coverity Project to assign CVSS metrics to defects ");
    group1.add_argument("--config", dest='config', required=True, help="CONFIG_FILE e.g cvss-rpt-config.properties");

    args = parser.parse_args()

    if (args.config):
        confVal = ConfigParseProperties(args.config)
        args.host = confVal.connectHost
        args.port = confVal.connectPort
        args.ssl = confVal.connectSsl
        args.username = confVal.connectUser
        args.password = confVal.connectPass

    if (args.host is None or
        args.port is None or
        args.username is None or
        args.password is None):
        print ("Must specify Connect server and authentication details in  properties file")
        parser.print_help()
        sys.exit(-1)

    defectServiceClient = DefectServiceClient(args.host, args.port, args.ssl, args.username, args.password)
    configServiceClient = ConfigServiceClient(args.host, args.port, args.ssl, args.username, args.password)
    
    if (args.noscore):
        cvssScoring = False
        
    if (args.noreport):
        cvssReport = False
    
    if (cvssScoring):
        # Parse CSV File 
        with open('Master_CWE_CVSS_Base_Score_Mapping-v1.0.1.csv') as csvFile:
            csvRead = csv.reader(csvFile)
            csvData = list(csvRead)
        cweList = [row[0] for row in csvData]
        colnHdr = csvData[0]
        
        # Get data from CC
        projectName = args.project
        projectDOs = configServiceClient.get_project(projectName)
        assert(len(projectDOs) == 1)
        projectDO = projectDOs[0]
        print ("Primary project:" + projectDO.id.name)
        #for stream in projectDO.streams:
            #dump (stream)

        lineNumber = None
        eventTag = None
        eventDescription = None
        streamNames = []
        for streamDO in projectDO.streams:
            streamNames.append(streamDO.id.name)
            triageStoreName = streamDO.triageStoreId.name
            print (triageStoreName)
        streamLinks = getattr(projectDO, 'streamLinks', [])
        for streamDO in streamLinks:
            streamNames.append(streamDO.id.name)       
        #print ("triage store: " + triageStoreName)
        
        for stream in streamNames:
            print ('Stream Name:' + stream + '\n')    
            mergedDefectDOs = defectServiceClient.get_merged_defects_for_stream(stream)
            for mergedDefect in mergedDefectDOs:
                #for attribKeyValuePair in mergedDefect.defectStateAttributeValues:
                    #if (attribKeyValuePair.attributeDefinitionId.name == 'cwe'):
                        #print ("CWE VECTOR field identified")         
                print ('\n')
                cid = mergedDefect['cid']            
                checker = mergedDefect['checkerName']
                #print ('CID:{} checker:{} '.format(cid, checker))
                
                try:
                    CWE = mergedDefect['cwe']
                except AttributeError:
                    CWE = 0

                try:
                    print ('CID:{}  Checker:{} CWE:{} Index:{}'.format(cid, checker, str(CWE), cweList.index(str(CWE))))
                except ValueError:
                    print ('Warning: CWE Data not found for the CWE. CWE=0 is assumed for CVSS calculations.. \nCID:{} CWE-Value:{}'.format(cid, str(CWE)))
                    CWE = 0
                    
                    
                filePathname = mergedDefect['filePathname']           
                #Build CVSS Vector:
                vectorStr = [cvssVersion]
                rowIndex = cweList.index(str(CWE))
                for vector in cvssMandatory:
                    vectorVal = ''
                    if (vectorFlag[vector]):
                        vectorVal = vector + ':' + cvssPrpVector[vector]
                    else:
                        colnIndex = colnHdr.index(vector)
                        vectorVal = vector + ':' + csvData[rowIndex][colnIndex]
                        #print (vector, csvData[rowIndex][colnIndex])
                    #print ('VectorVal:' + vectorVal)
                    vectorStr.append(vectorVal)
                    
                s = "/" 
                baseVector = s.join(vectorStr)           
                #print ('BaseVector:' + baseVector)
                baseScore =  get_baseScore(baseVector)           
                severity = get_severity(baseScore)   
                vectorStr.clear()                
                   
                # Data-Structs to process & update CVSS data in CC
                triageCmp = {}
                triageData = {}
                cvssData = []
                   
                # Process CVSS Metrics data & Update Connect
                triageInfoDOs = defectServiceClient.get_triage_info(triageStoreName, cid)
                if (triageInfoDOs):
                    triageInfoDO = triageInfoDOs[0]
                    for attribKeyValuePair in triageInfoDO.attributes:
                        if attribKeyValuePair.attributeDefinitionId.name in cvssMetrics:
                            triageData[attribKeyValuePair.attributeDefinitionId.name] = attribKeyValuePair.attributeValueId.name
                            
                    if (triageData['CVSS_Audited'] == 'Yes'):
                        #print ('triageData CVSS_BaseVector:{}'.format(triageData['CVSS_Vector']))
                        auditBaseStr = triageData['CVSS_Vector']
                        baseScore =  get_baseScore(triageData['CVSS_Vector'])
                        if (baseScore == -1):
                            print('For CID:{}, CVSS BaseVector:{} is Invalid. Skipping Base Score calculation..'.format(cid, triageData['CVSS_Vector']))
                            sys.exit(-1)
                        severity = get_severity(baseScore)
                        print ('Audited CVSS_Vector:{}'.format(auditBaseStr)) 
                        print ('Updating CVSS Data [CVSS_BaseScore:{} , CVSS_Severity:{}]'.format(str(baseScore), severity))
                        defectServiceClient.update_cvss_audited(triageStoreName, cid, baseScore, severity)
                    else:
                        print ('CVSS_BaseScore:{} CVSS_Severity:{}'.format(str(baseScore), severity))
                        # Update cvss data only if triaged fields are dis-similar 
                        data = [str(baseScore), severity, baseVector, 'No']
                        cvssData.extend(data)
                        for w, cvssMetric in enumerate(cvssMetrics):
                            triageCmp[cvssMetric] = cvssData[w]                    
                        triageCmp.pop('CVSS_Audited', None)
                        triageData.pop('CVSS_Audited', None)
                        print ('Updating CVSS Data:{}'.format(triageCmp))
                        if (triageCmp == triageData):
                            continue
                        else:
                            try:
                                defectServiceClient.update_cvss(triageStoreName, cid, baseVector, baseScore, severity)
                                print ('Old CVSS Triage Record:{}'.format(triageData))
                            except:
                                print("Exiting. Failed to update CVSS metrics. See traceback for additional info... ", sys.exc_info()[0])
                                sys.exit(-1)
                else:
                    # No triage changes registered yet. Insert CVSS Metrics for the first time
                    try:
                        defectServiceClient.update_cvss(triageStoreName, cid, baseVector, baseScore, severity)
                        print ('First Insert: CVSS_Vector:{} CVSS_BaseScore:{} CVSS_Severity:{} \n'.format(baseVector, str(baseScore), severity))
                    except:
                        print("'Exiting. One or more CVSS attribute appears to be unavailable or defined incorrectly..", sys.exc_info()[0])
                        sys.exit(-1)
                        
    if (cvssReport):
        print ("\nGenerating CVSS Report..")
        javafile = "C:\\Users\\rprithvi\\Desktop\\\Py_Data\\ExampleProgram.java"
        currDir = os.getcwd()
        print (currDir)
        #dirname, filename = os.path.split(os.path.abspath(__file__))
       
        cmd = currDir + '\lib\cvss-report-generator.bat'
        arg = "cvss_report_config.properties"
        arguments = ["testSecRpt.covsr", '--output', 'samp.pdf', '--password', 'console']
        m = "//"
        path = cmd.split('/')
        print ('Path:' + str(path))
        #cmd = m.join(path)
        print (cmd)
        argument = m.join(arguments)
        #cmd = cmd + " " + argument
        dir, file = os.path.split(cmd)
        #print (dir, file)
        os.chdir(dir)
        
        
        subprocess.call([path, arg])
        os.chdir("C:\\Users\\rprithvi\\Desktop\\Py_Data\\ps-scripts-master\\cvss-report\\lib")
        subprocess.call(["C:\\Users\\rprithvi\\Desktop\\Py_Data\\ps-scripts-master\\cvss-report\\lib\\cvss-report-generator.bat"])
        #print ("\nExecuting Ping Command:")
        #subprocess.call(["ping", "www.google.com"])
        #print ("\nExecuting simple Java Program:")
        #subprocess.call(["javac", javafile])
        #subprocess.call(["java", "ExampleProgram"])
        #subprocess.Popen(["samp.pdf"],shell=True)
        #subprocess.call(["samp.pdf"])
        
        
        
        
        