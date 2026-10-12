import subprocess
from datetime import datetime
import sys
import os
import csv
import re
from urllib.parse import urlparse

#****************************************************************************************
# this function verify if the argument given is an URL
def est_url(url):
    try:
        result=urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        return False

# this function verify if the argument given is a request 
def est_requete(req):
    exp_reg= expression_reguliere = re.compile(
        r'\b(SELECT|UPDATE|DELETE|INSERT INTO|CREATE|ALTER|DROP|GRANT|REVOKE)\b',
        re.IGNORECASE)
    return re.search(exp_reg,req) is not None

#*****************************************************************************************

# read the arguements 
arg=sys.argv

#*****************************************************************************************
                 #verify if the arguments given are correct or not

if (('-u' in arg)and('--sql-query' in arg)):
    if (est_url(arg[2])):
        if (est_requete(arg[-1])):
            commande_sqlmap = ['python','sqlmap.py']+arg[1:]
        else:
            print("verify your request")
            exit()
    else:
        print("verify your URL")
        exit()
else:
    print("Verify that you input correctly -u or --sql-query")
    exit()

#*****************************************************************************************

#*****************************************************************************************
                   #extract the name of columns from the request
deb="SELECT"
fin="FROM"

#find the start point of the ""deb"" variable in the request
temp1=(arg[-1].upper()).find(deb)

#find the start point of the ""fin"" variable in the request
temp2=(arg[-1].upper()).find(fin)

#select the request from the arguments given bu the user in command line
temp_res=arg[-1]

#start selection of the columns names after the ""deb"" variable
T=len(deb)-temp1+1
temp_res=temp_res[T:temp2]

#split the String that contains columns name 
temp_res=(temp_res.strip()).split(',')

#******************************************************************************************

#******************************************************************************************
                    #process the request

res=subprocess.check_output(commande_sqlmap)

#res=subprocess.run(commande_sqlmap,capture_output=True, text=True)

#view the result of processing the resquest
res = res.decode('utf-8')
print(res)


# Select actuel time
heure_actuelle = datetime.now()
heure_formattee = heure_actuelle.strftime("%H:%M:%S")

# ""m_deb"" variable is a string that represents the start point of showing the result of the request   
m_deb="["+str(heure_formattee)+"]"+" [INFO] fetching SQL SELECT statement query output:"

# ""m_fin"" variable is a string that represents the end point point of showing the result of the request
m_fin="["+str(heure_formattee)+"]"+" [INFO] fetched data logged to text files under"

#""debut_message"" contains the position of the ""m_deb"" variable in the result
debut_message = res.find(m_deb)

#""fin_message"" contains the position of the ""m_fin"" variable in the result
fin_message = res.find(m_fin)

#select a part of the result that is between ""m_deb"" variable and ""m_fin"" variable
message = res[debut_message:fin_message].strip()


lignes = message.splitlines()

# ""donnees_sauvegarder"" variable is a list of dictionaries
donnees_sauvegarder = []

# loop on the ""lignes"" variable
for ligne in lignes:
    # verify if this line contain [*]
    if ligne.startswith("[*]"):
        # extract data after '[*]'
        v_temp=(ligne[4:].strip()).split(',')
        d_temp={}
        for i in range(len(temp_res)):
            # add for every column from ""temp_res"" variable a value from ""v_temp"" variable 
            d_temp.update({temp_res[i]:v_temp[i]})
            
        # add the dictionarie in the list
        donnees_sauvegarder.append(d_temp)

#*****************************************************************************************************
    
            # create a file named ""data_save.csv"" in same repositories with this script file
            
file_csv="data_save.csv"

if(len(donnees_sauvegarder)!=0):# if the process of the request send data
    with open(file_csv,mode='w',newline='') as file_csv:
        # write the header of this CSV file
        writer=csv.DictWriter(file_csv,fieldnames=temp_res)
        writer.writeheader()
        # loop on the list of dictionaries named ""donnees_sauvegarder"" to wite its content on the CSV file
        for part in donnees_sauvegarder:
            writer.writerow(part)
        # if the data is successfully saved in the CSV file this message show the place of the file
        print("data saved in csv format under "+"'"+os.path.realpath("data_save.csv")+"'")
else:
    print("data don't exist to create CSV file")
    
#********************************************************************************************************
