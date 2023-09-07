#for each line in the CIS control, decide which section it is part of, i.e. Description, Rationale, etc
#content for each section is split across multiple lines. First thing to do is identify which section (i.e. bucket) a line belongs to
#If it contains a keyword that defines a section, drop the line into that corresponding bucket, if not then the bucket for the previous line is used as it must be part of that section
#DD 07/04/2023

import csv
import traceback

input_file = "input.txt"
output_file = "output.csv"

##################################################
## Functions #####################################

def func_define_bucket(line, bucket):
    #this function defines the bucket a line is moved into based on specific keywords in the line
    #if there are no keywords, the bucket from the previous line is used
        if line[:1].isnumeric() and ("(L1)" in line or "(L2)" in line or "(NG)" in line):
            bucket = list_title
        elif "Description:" in line:
            bucket = list_description
        elif "Impact:" in line:
            bucket = list_impact
        elif "Rationale:" in line:
            bucket = list_rationale
        elif "Remediation:" in line:
            bucket = list_remediation
        elif "Default Value:" in line:
            #bucket = list_default_value
            bucket = list_bin #not wanted, drop
        elif " | P a g e" in line or "Page" in line:
            bucket = list_bin #not wanted, drop
        elif "Profile Applicability:" in line:
            bucket = list_profile #not wanted, drop
        elif "Audit:" in line:
            bucket = list_bin #not wanted, drop
        elif "References:" in line:
            bucket = list_bin #not wanted, drop
        elif "CIS Controls:" in line:
            bucket = list_bin #not wanted, drop
        else:
            bucket = bucket
        return bucket


def func_export_data_to_csv(list_title, list_description, list_impact, list_rationale, list_remediation, list_default_value):
    #create a list (list_whiterabbit) of lists, then print it to csv
    #join the contents of each list, such as list_description, together, add it to list_whiterabbit, then print to csv
        
    list_whiterabbit = [] #clear the list being used in this function
        
    #join the title list into one string, i.e. the bucket with the parts of the title in it
    combined_list_title = " ".join(list_title)
    
    #for debugging only - export and print the list title. Comment out the line below when debugging not needed
    #list_whiterabbit.append(combined_list_title)
    
    #take the combined_list_title and extract the section number
    section_number = func_get_section_number_list(combined_list_title)
    list_whiterabbit.append(section_number)
    
    #Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
    #Decision: do you want the full title as above, or the title and recommendation separately
    #for the full title, use func_get_section_title below
    #to have them separate, use func_get_section_title1 and func_get_recommendation
    
    #take the combined_list_title and extract the title
    #i.e. 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
    #some titles have words like "don't" in them, and the apostrophe causes problems. Change these to "dont"
    title = func_change_words_with_apostrophes(combined_list_title)
    title = func_get_section_title(title)
    #title = func_get_section_title1(title) #use this function if splitting the Title and Recommendation
    list_whiterabbit.append(title)
    
    #take the combined_list_title and extract the recommendation, if there is one
    #i.e. 1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
    #recommendation = func_get_recommendation(combined_list_title)
    #list_whiterabbit.append(recommendation)
    
    #get the profile level of the hardening item - L1, L2, etc
    profile_level = get_profile_applicability_level(combined_list_title)
    list_whiterabbit.append(profile_level)
    
    #join the Profile Applicability text and send it to the overall list (whiterabbit) for exporting to csv
    combined_list_profile = ", ".join(list_profile)
    combined_list_profile = func_remove_title_keyword(combined_list_profile)
    combined_list_profile = combined_list_profile.strip() #this list seems to bring in spaces, so strip them out
    list_whiterabbit.append(combined_list_profile)

    #join the Description text and send it to the whiterabbit list for exporting to csv
    combined_list_description = " ".join(list_description)
    combined_list_description = func_remove_title_keyword(combined_list_description)
    list_whiterabbit.append(combined_list_description)

    #join the Impact text and send it to the whiterabbit list to be exported to csv
    combined_list_impact = " ".join(list_impact)
    combined_list_impact = func_remove_title_keyword(combined_list_impact)
    list_whiterabbit.append(combined_list_impact)

    #join the Rationale text and send it to the overall list for exporting to csv
    combined_list_rationale = " ".join(list_rationale)
    combined_list_rationale = func_remove_title_keyword(combined_list_rationale)
    list_whiterabbit.append(combined_list_rationale)
    
    #join the Remediation text and send it for exporting to csv
    combined_list_remediation = " ".join(list_remediation)
    combined_list_remediation = func_remove_title_keyword(combined_list_remediation)
    list_whiterabbit.append(combined_list_remediation)

    #write the contents of the whiterabbit list out to csv
    writer.writerow(list_whiterabbit)

def func_get_section_number_list(line):
    #get the section number, i.e. 18.2.3.5, by taking everything left of the first space in the line
    space_position = line.find(" ")
    line1 = line
    line2 = line1[:space_position]
    return line2

def func_get_section_title(line):
    #1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
    #Get the section title by taking everything right of the first space
    space_position = line.find(" ")
    line1 = line
    line2 = line1[space_position:]
    return line2

def func_get_section_title1(line):
    #1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
    #Get just the section title, i.e. Enforce password history
    first_apostrophe = line.find("'") + 1
    second_apostrophe = line.find("'",first_apostrophe)
    title = line[first_apostrophe:second_apostrophe]
    return title

def func_get_recommendation(line):
    #1.1.1 Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
    #Get just the recommendation, i.e. 24 or more password(s)
    if line.find("is set to"):
        checkpoint01 = line.find("is set to") #set a checkpoint after the first few apostrophes
    elif line.find("to include"):
        checkpoint01 = line.find("to include") #set a checkpoint after the first few apostrophes
    #sometimes there is no recommendation, so return blank, i.e. "2.2.14 Configure 'Create symbolic links' (Automated)"
    if checkpoint01 > 0:
        first_apostrophe = line.find("'",checkpoint01) + 1
        second_apostrophe = line.find("'",first_apostrophe)
        recommendation = line[first_apostrophe:second_apostrophe]
        return recommendation
    else:
        return ''

def get_profile_applicability_level(line):
	first_apostrophe = line.find("'")
	text = line[:first_apostrophe]
	if "(L1)" in text:
		result = "L1"
	elif "(L2)" in text:
		result = "L2"
	elif "(BL)" in text:
		result = "BL"
	if "(NG)" in text:
		result = "NG"
	return result

def func_remove_L(line):
    #This function removes the (L1) and (L2) from the titles for readability sake
    if "(L1)" in line:
        line = line.replace("(L1) ","")
    elif "(L2)" in line:
        line = line.replace("(L2) ","")
    return line

def func_remove_automated_keyword(line):
    if "(Automated)" in line:
        line = line.replace("(Automated)","")
        line = line.strip()
    return line

def func_change_words_with_apostrophes(line):
    if "don't" in line:
        line = line.replace("don't","dont")
    elif "Don't" in line:
        line = line.replace("Don't","Dont")
    line = line.strip()
    return line

def func_remove_funny_unicode(line):
    #remove troublesome unicode characters
    if '\uf0b7' in line:
        line = line.replace('\uf0b7','')
    elif '\u202f' in line:
        line = line.replace('\u202f','')
    elif '\u2022' in line:
        line = line.replace('\u2022','')
    return line

def func_remove_profile_level_details(line):
    #remove the Level 1 and Level 2 from the profile applicability
    if 'Level 1 - ' in line:
        line = line.replace('Level 1 - ','')
    elif 'Level 2 - ' in line:
        line = line.replace('Level 2 - ','')
    return line

def func_remove_title_keyword(combined_list):
    #this removes the keywords (Description, Rationale, etc) before the line is printed to csv, as these will already be in the csv header row
    if combined_list[:12] == "Description:":
        combined_list = combined_list[13:]
    elif combined_list[:22] == "Profile Applicability:":
        combined_list = combined_list[23:]
    elif combined_list[:7] == "Impact:":
        combined_list = combined_list[8:]
    elif combined_list[:10] == "Rationale:":
        combined_list = combined_list[11:]
    if combined_list[:12] == "Remediation:":
        combined_list = combined_list[13:]
    #elif combined_list[:14] == "Default Value:":
        #combined_list = combined_list[15:]
    return combined_list
    
## End of Functions ##############################
##################################################

#open the input and output files in read only and write only modes
f = open(input_file, "r", encoding='utf-8') #input file
output_file = open(output_file, 'w', newline='') #output file


#define & clear the lists we will be using
list_title = []
list_profile = []
list_description = []
list_impact = []
list_rationale = []
list_remediation = []
list_default_value = []
list_bin = []
list_csv_header = ["Section", "Title", "Profile Level", "Profile", "Description", "Impact", "Rationale", "Remediation"]

#create the csv writer 
writer = csv.writer(output_file)

#write header row to csv
writer.writerow(list_csv_header)

#need to set a value for the opening bucket, as it is needed for the first function in the loop below
bucket = list_bin


for line in f:
    try:
        if line[:1].isnumeric() and ("(L1)" in line or "L2" in line or "NG" in line) and len(list_title)>0:
            #from the title line, capture the section number and title.
            #section_number = func_get_section_number(line)
            #if the script sees a title line, and the buckets are already full, it means this is the start of a new section. Print the contents of the existing buckets to csv and clear them in readiness for the next section
            #Some lines have the title keywords in them, but not the other fields, i.e. the table of contents. We don't want these, so only print to csv if there is something in the Description list
            if list_description:
                func_export_data_to_csv(list_title, list_description, list_impact, list_rationale, list_remediation,list_default_value)
            #clearing the buckets...
            list_title = []
            list_profile = []
            list_description = []
            list_impact = []
            list_rationale = []
            list_remediation = []
            list_default_value = []
            list_bin = []
        line = func_remove_funny_unicode(line) #remove troublesome unicode characters
        line = line.strip() #remove any spaces before or after the line
        bucket = func_define_bucket(line, bucket) #find out which bucket each line is going to be part of/drop in to
        line = func_remove_automated_keyword(line) #remove the "(Automated)" word
        line = line.replace("\n","") #remove \n from the end of the lines
        line = func_remove_profile_level_details(line) #remove the Level 1 and Level 2 from the profile applicability
        #print(bucket, line)
        #input()
        bucket.append(line) #add the line to the list (bucket) represented by the bucket name
    except Exception as exception:
        print("Exception: {}".format(type(exception).__name__))
        print("Exception message: {}".format(exception))
        print(traceback.format_exc())
        print(line, "\n")
        input()

#finally, export the last bucket to csv
func_export_data_to_csv(list_title, list_description, list_impact, list_rationale, list_remediation, list_default_value)


f.close()
output_file.close()

#final prompt, useful for troubleshooting any issues during the run of the script
print("\n-- End of File --------------------------------------------------------------")
input()