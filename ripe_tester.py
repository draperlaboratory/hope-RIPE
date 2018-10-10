#!/usr/bin/python

# Developed by Nick Nikiforakis to assist the automated testing
# using the RIPE evaluation tool
#
# Released under the MIT license (see file named LICENSE)
#
# This program is part the paper titled
# RIPE: Runtime Intrusion Prevention Evaluator
# Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
#              Mariam Kamkar and Wouter Joosen
# Published in the proceedings of ACSAC 2011, Orlando, Florida
#
# Please cite accordingly.
#
# Modified for RISC-V by John Merrill

import os, sys, subprocess, time, signal, argparse
from termcolor import colored

code_ptr = ['ret', 'funcptrstackvar', 'funcptrstackparam', 'funcptrheap',
'funcptrbss', 'funcptrdata', 'structfuncptrstack', 'structfuncptrheap',
'structfuncptrdata', 'structfuncptrbss', 'longjmpstackvar', 'longjmpstackparam', 
'longjmpheap', 'longjmpdata', 'longjmpbss','bof', 'iof', 'leak'];

funcs = ['memcpy', 'strcpy', 'strncpy', 'sprintf', 'snprintf', 'strcat',
'strncat', 'sscanf', 'homebrew'];

locations = ['stack','heap','bss','data'];

attacks = ['shellcode', 'returnintolibc', 'rop', 'dataonly'];
techniques = []
count_only = 0
output = ''

width = int(os.popen('stty size', 'r').read().split()[1])
color = lambda x,y: colored(x, y, attrs=['bold'])
line = lambda x: color('-'*x, 'white')
bold_line = lambda x: color('='*x, 'white')

def print_attack(cmdargs, status):
	params = cmdargs.split('_')[1:]
	for idx, param in enumerate(params):
		params[idx] = param[2:]
	
	result = ''
	if status == 1:
		result = color('OK', 'green')
	else:
		result = color('FAIL', 'grey')

	print('Technique: ' + params[0])
	print('Attack code: ' + params[1])
	print('{0:50}{1:}'.format('Target Pointer: ' + params[2], 'Result: ' + result))
	print('Location: ' + params[3])
	print('Function: ' + params[4])
	print(line(64))

def is_attack_possible ( attack, tech, loc, ptr, func ):

	if attack == 'shellcode':
		if func != 'memcpy' and func != 'homebrew':
			return 0

	if attack == 'dataonly':
		if ptr not in ['bof', 'iof', 'leak']:
			return 0

		if (ptr == 'iof' or ptr == 'leak') and tech == 'indirect':
			return 0

		if tech == 'indirect' and loc == 'heap':
			return 0
	elif ptr in ['bof', 'iof', 'leak']:
		return 0;

	if attack == 'rop' and tech != 'direct':
		return 0	

	if tech == 'indirect' and ptr == 'longjmpheap' and loc == 'bss':
		if func != 'memcpy' and func != 'strncpy' and func != 'homebrew':
			return 0

	if tech == 'direct':
		if (loc == 'stack' and ptr == 'ret'):
			return 1
		elif attack != 'dataonly' and ptr.find(loc) == -1:
			return 0
		elif ptr == 'funcptrstackparam':
			if func == 'strcat' or func == 'snprintf' or func == 'sscanf' or func == 'homebrew':
				return 0
		elif ptr == 'structfuncptrheap' and attack != 'shellcode' and loc == 'heap':
			if func == 'strncpy':
				return 0
	return 1

# parse args
parser = argparse.ArgumentParser(description='frontend for RIPE')
parser.add_argument('-t', help='Techniques [direct|indirect|both] (both by default)', default='both')
parser.add_argument('-f', help='Run tests with all functions (memcpy() only by default)', default=False, action='store_true')
parser.add_argument('-r', help='Simulator command', default='spike pk', action='store_true')
parser.add_argument('-o', help='Send output to file (default stdout)', nargs=1)
args = parser.parse_args()

print args

if args.t == 'both':
	techniques = ['direct','indirect'];
else:
	techniques = [args.t]

if not args.f:
	funcs = ['memcpy']

if args.r:
	run_cmd = args.r

if args.o:
	color = lambda x,y:x
	sys.stdout = open(args.o[0], 'w')

# rebuild RIPE
os.system('make > /dev/null 2>&1') 

print bold_line(width)
print color('RIPE: The Runtime Intrusion Prevention Evaluator for RISCV', 'white')
print bold_line(width)

total_ok=0;
total_fail=0;
total_np = 0;

start_time = time.time()

for attack in attacks:
	for tech in techniques:
		for loc in locations:
			for ptr in code_ptr:
				for func in funcs:
					os.system('rm -f out/out.text')
					cmdargs = 'build/ripe_attack_generator ' + '-t ' + tech + ' -i ' + attack + ' -c ' + ptr + ' -l ' + loc + ' -f ' + func
					cmdline= run_cmd + ' ' + cmdargs + ' 1> out/out.text 2>/dev/null'

					if is_attack_possible (attack, tech, loc, ptr, func) == 0:
						total_np += 1
					
					else:
						if count_only == 0:
							os.system(cmdline)
							time.sleep(0.5)
						else:
							os.system('touch out/out.text')
						
						# Evaluate attack status
						status = 0
						log = open('out/out.text','r')
						log.seek(0)

						if log.read().find('success') != -1:
							status = 1
							total_ok += 1
						
						log.seek(0)

						if status == 0:
							total_fail += 1

						# print attack
#						print_attack(cmdargs, status)
						print(cmdargs, status)

# do summary
total_attacks = total_ok + total_fail;
end_time = time.time() - start_time
avg_time = end_time / (total_attacks)

print color('SUMMARY\n', 'white') + line(64)
print 'Total ' + color('OK', 'green') + ': ' + str(total_ok)
print 'Total ' + color('FAIL', 'grey') + ': ' + str(total_fail)
print 'Total Attacks Executed: ' + str(total_attacks)
print 'Total time elapsed: ' + str(int(end_time / 60)) + 'm ' + str(int(end_time % 60)) + 's'
print 'Average time per attack: ' + '{0:.2f}'.format(avg_time) + 's'
