import os,stat
import argparse
from ctypes import *

#load the shared object file

#files= os.listdir('lz4_crash')
#i=0
url_default = "mongodb://10.0.0.16:27017"
db_default = "lz4_1"
##############################################3
binary_default = "/home/cx/workspace/target_group/lz4/lz4"
input_default = "/home/cx/workspace/target_group/lz4/lz4_crash_1"
log_default = "/home/cx/workspace/asan.log.28665"
cmd_default = "\n"
bug_list = []
##################################################################################
def load_crash(url,db,input):
	loadMongo = CDLL('./crash-analyze/loadMongo.so')
	loadMongo.load_mongoSeed(url,db,input)
def auto_input(in_dir,cmd):
	if cmd.index('@@') == -1:
		print ("must provide @@ as input location!!")
		exit(0)
	if os.path.isdir(in_dir):
		files = os.listdir(in_dir)
		for f in files:
			if not os.path.isdir(f):
				#file = open('lz4_crash/'+file)
				print (f + '\n')

				tmp = cmd.split('@@')
				output = tmp[0] + ' ' + in_dir + '/' + f + " "+ tmp[1]
				print (output)
				os.system(output)


def analyze(out_dir):
	if os.path.isdir(out_dir):
		outs = os.listdir(out_dir)
		for out in outs:
			if not os.path.isdir(out):
				#os.chmod(out, stat.S_IREAD)
				f = open(out_dir+"/"+out, 'r')
				process_out(f)
	else:
		#os.chmod(out_dir,stat.S_IREAD)
		f = open(out_dir,'r')
		process_out(f)

	for i in range(len(bug_list)):
		if len(bug_list[i].items()) == 3:
			print ("bug name: " + bug_list[i].get("bug"))
			print ("location: " + bug_list[i].get("location"))
			print ("function:" + bug_list[i].get("function"))
		else:
			print ("bug name: " + bug_list[i].get("bug"))
			print ("state" + bug_list[i].get("state"))

def process_out(f):
	#print ("now processing " + out + "\n")
	##f = open(out_dir + '/' + out)
	while(1):
		line = f.readline()
		if line == "":
			break
		if line.find("SUMMARY")>=0:
			tmp = line.split(" ")
			bug = tmp[2]
			loc = tmp[3]
			func = tmp[4]

			## filter
			if bug == "heap-use-after-free" or bug == "heap-buffer-overflow" or bug == "stack-buffer-overflow" or bug == "global-buffer-overflow" or bug == "stack-use-after-return" \
					or bug == "stack-use-after-scope" or bug == "initialization-order-fiasco":

				item = {"bug": bug, "location": loc, "function": func}
				if bug_list.count(item) == 0:
					bug_list.append(item)

			elif bug.isdigit():
				item = {"bug": "memory leak", "state":line}

			else:
				continue

			if bug_list.count(item) == 0:
				bug_list.append(item)

	f.close()

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="your script description")
	group =  parser.add_mutually_exclusive_group()
	group.add_argument('--download',  action='store_true', help='download crash files from database, with -u,-t and -i')
	group.add_argument('--autoinput',  action='store_true',help='auto input crash files, with -i,-b and -p')
	group.add_argument('--analyze',  action='store_true', help='analyze the log file to find true bugs, with -l')
	group.add_argument('--all', action='store_true', help='download+auto input+analyze, with -c, -t')
	#######################################################################
	parser.add_argument('--binary', '-b', help='path of target binary',default=binary_default)
	parser.add_argument('--input', '-i',  help='path of crash input files',default=input_default)
	parser.add_argument('--cmd', '-c',  help='cmd, using @@ to represent the location of input',default=cmd_default)
	parser.add_argument('--log', '-l',help='path of bug log dir',default=log_default)
	parser.add_argument('--url', '-u', help='url of mongo',default=url_default)
	parser.add_argument('--target', '-t', help='target name in mongo(db name)',default=db_default)

	args = parser.parse_args()

	if args.download:
		if not args.input:
			print "must define a input dir"
			exit(0)
		else:
			load_crash(args.url,args.target,args.input)
	if args.autoinput:
		if not args.input or not args.cmd or not args.log:
			print "must define a input dir, a cmd and a log path"
			exit(0)
		else:
			os.environ['ASAN_OPTIONS']= "detect_leaks=1:log_path="+args.log
			print(os.getenv("ASAN_OPTIONS"))
			auto_input(args.input,args.cmd)
	if args.analyze:
		if not args.log:
			print "must define a log path"
			exit(0)
		else:
			analyze(args.log)
	if not args.download and not args.autoinput and not args.analyze:
		print "must define a mode from '--download' '--autoinput' '--analyze'"
		exit(0)