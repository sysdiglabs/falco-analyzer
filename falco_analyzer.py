#!/usr/local/bin/python
# Requires Python3
# Install dependencies with:
#  pip install ruamel.yaml
# See usage with:
#  python merge_tags.py

from ruamel.yaml import YAML
#from slugify import slugify
import sys
import os


def merge_yamls(rule_file, tag_file, output_file):
    
    yaml=YAML(typ='rt')
    yaml.width = 4096 # prevent line wrap
    yaml.preserve_quotes = True

    indexed_rules_tags={}
    with open(tag_file, "r") as file:
        rules_tags = yaml.load(file)
        for rule in rules_tags:
            indexed_rules_tags[rule['rule']]=rule['tags']
    
    stats={'lists':0, 'macros':0, 'rules':0, 'rules_unmodified':0, 
    'rules_modified':0, 'rules_notfound':0, 'rules_notags':0, 'other':0}
    other_items=[]
    rules_not_found=[]
    rules_no_tags_key=[]
    required_engine_version=0

    with open(rule_file, "r") as file:
        falco_doc = yaml.load(file)
        
        if (falco_doc is None):
            print("** Error: YAML document empty")
            exit()

        for item in falco_doc:
            if item.get("list") != None:
                stats['lists']+=1
                continue
            if item.get("macro") != None:
                stats['macros']+=1        
                continue    
            if item.get("required_engine_version") != None:
                required_engine_version=item.get("required_engine_version")
                continue

            if item.get("rule") == None:
                # Something that is not a rule, a macro or a list
                stats['other']+=1
                other_items.append(item)
                continue

        
            # A rule
            stats['rules']+=1

            if item.get("tags") == None:
                # Rule doesn't have a 'tags' key
                stats['rules_notags']+=1
                rules_no_tags_key.append(item.get("rule"))
                item["tags"]=[]
                # We still will add tags to this rule
            
            if item.get("rule") not in indexed_rules_tags.keys():
                # Tags file doesn't have a rule with same name
                rules_not_found.append(item.get("rule"))
                continue
            if len(indexed_rules_tags[item.get("rule")]) == 0:
                # Tag file doesn't have new tags for this rule
                stats['rules_unmodified']+=1
                continue

            # Append non existing tags
            for newtag in indexed_rules_tags[item.get("rule")]:
                if ( not newtag in item['tags']):
                    item['tags'].append(newtag)
            
            stats['rules_modified']+=1

        # Write output file

        with open(output_file, "w") as stream:
            stream.write('# Merged tags from ' + os.path.basename(tag_file) +  '\n\n')
            yaml.dump(falco_doc, stream)
            stream.close()


        # Output results

        if ( len(rules_not_found) > 0 ):
            print ("\nRules not found:")
            for rule in rules_not_found: 
                print (rule)
        
        if ( len(rules_no_tags_key) >0 ):
            print ("\nRules without 'tags' keyword:")
            for rule in rules_no_tags_key:
                print (rule)

        if ( len(other_items) > 0 ):
            print ("\nOther elements:")
            for item in other_items: 
                print (item)

        print ("\nLists: ", stats['lists'])
        print ("Macros: ", stats['macros'])
        print ("Rules: ", stats['rules'])
        print ("  Modified rules: ", stats['rules_modified'])
        print ("  Unmodified rules: ", stats['rules_unmodified'])
        print ("  Rules not found: ", len(rules_not_found) )
        print ("  Rules no tags key: ", stats['rules_notags'])
        print ("required_engine_version: ", required_engine_version)
        print ("Other: ", len(other_items) )

        if ( len(rules_not_found) > 0 ): 
            sys.exit(1)
        sys.exit(0)

def read_rules_from_file(input_falco_rules_file): 
    yaml=YAML(typ='rt')
    yaml.width = 4096 # prevent line wrap
    yaml.preserve_quotes = True
    
    rules=[]

    with open(input_falco_rules_file, "r") as file:
        falco_doc = yaml.load(file)
        print(input_falco_rules_file + " has yaml nodes", len(falco_doc))
        for item in falco_doc:
            # print(item)
            # exit()
            if item.get("rule") != None:
                # print(item.get("rule"))
                rules.append(item)
        
    return rules

def get_tags_from_prefix(tags, prefix):
    separator = ", "
    result = separator
    for tag in tags:
        if str.startswith(tag, prefix) and tag != prefix:
            # print("Found " + prefix + " in " + tag)
            result = result + tag + separator
        # else:
            # print("Not found " + prefix + " in " + tag)
    result = result [len(separator): len(result)- len(separator)]
    return result

def starts_with_any(tag, prefixes):
    for prefix in prefixes:
        if str.startswith(tag, prefix):
             # and tag != prefix:
            return True
    return False

def get_csv_tags(input_falco_rules_file, output_csv_file):
    
    rules = read_rules_from_file(input_falco_rules_file)
    print("Rules found: ", len(rules))
    
    separator = ","
    quote = "\""
    eol = "\n"

    i=1
    filename=os.path.basename(input_falco_rules_file)
    prefixes = ["source=", "PCI", "NIST_800-190", "NIST_800-53", "mitre", "SOC2"]
    fields = prefixes + ["rule", "file", "position"]
    
    header = ""
    for field in fields:
        header += separator + field
    header=header[len(separator):len(header)]

    with open(output_csv_file, "w") as stream:
        stream.write(header + eol)
        for item in rules:
            if not 'tags' in item:
                continue
            line = ""
            for prefix in prefixes:
                tags = get_tags_from_prefix(item['tags'], prefix)
                line += quote + tags + quote + separator
            line += quote + item['rule'] + quote + separator + filename + separator + str(i) + eol
            # print(line)
            stream.write(line)
            i=i+1

        stream.close()

def get_rules_md(input_falco_rules_file, output_md_file):
    rules = read_rules_from_file(input_falco_rules_file)

    eol = "\n"
    title_prefix=eol + "## "
    desc_prefix=""
    tags_prefix="Tags: "
    avoid_tag_starts = ["PCI", "NIST_800-190", "NIST_800-53", "SOC2", "aws_cis", "pci_dss_"]
    tag_separator=", "

    with open(output_md_file, "w") as stream:
        stream.write("# Rules" + eol) 
        for item in rules:
            line = ""
            if not 'rule' in item:
                continue
            line += title_prefix + item['rule'] + eol
            if 'desc' in item:
                line += desc_prefix + item['desc'] + eol
            if 'tags' in item:
                tags_line=""
                for tag in item['tags']:
                    if not starts_with_any(tag, avoid_tag_starts):
                        tags_line += tag_separator + tag 
                if tags_line != "":
                    tags_line = tags_line[len(tag_separator):]
                    line += tags_prefix + tags_line + eol
            stream.write(line)

        stream.close()


def show_help(arguments=[]):
    print("Usage:")
    print("python3 falco_analyzer.py [command] [parameters]")
    print("")
    print("Example:")
    print("python3 falco_analyzer.py merge_tags rule_file.yaml tag_file.yaml output_file.yaml")
    print("")
    print("Commands")
    print("  help")
    print("     Show this help")
    print("  merge_tags [input_falco_rules_file] [tags_file] [output_file]")
    print("     Merges tags to rules from input file, and outputs new rules to a new file.")
    print("  get_csv_tags [input_falco_rules_file] [output_csv_file]")
    print("     Writes a CSV file with a Falco rule per row, with different tags used on each one")
    print("  get_rules_md [input_falco_rules_file] [output_md_file]")
    print("     Writes a markdown file with all Falco rule titles, descriptions and tags, except those filtered")
    exit()

def merge_tags_intro(arguments):
    if (len(arguments)<3+2):
        show_help()
    merge_yamls(arguments[2], arguments[3], arguments[4])

def get_csv_tags_intro(arguments):
    if (len(arguments)<2+2):
        show_help()
    get_csv_tags(arguments[2], arguments[3])
    exit()


def get_rules_md_intro(arguments):
    if (len(arguments)<2+1):
        show_help()
    get_rules_md(arguments[2], arguments[3])

def main():
    if len(sys.argv)<=1:
        show_help()
    
    switcher = {
        'merge_tags': merge_tags_intro,
        'get_csv_tags': get_csv_tags_intro,
        'get_rules_md': get_rules_md_intro,
        'help': show_help
    }
    if sys.argv[1] not in switcher:
        show_help()
 
    func= switcher.get(sys.argv[1], lambda: show_help([]) )
    return func(sys.argv)

if __name__ == "__main__":
    main()