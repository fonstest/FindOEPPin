from os.path import isfile, isdir, join
from os import listdir, rename
import subprocess
import time
import sys
import shutil

'''
To use this script:
  1) Put the malwares in the malware_folder (E:\Malwares)
  2) Create a work_folder where the malwares will be copied to and run (C:\Users\phate\Desktop\MalwareTests)
  3)Create a Result folder(test_results) where the results of the unpacking will be saved (E:\Results)
  4) Run the tool from the pin directory to avoid Scyllax86.dll problem (dll not found) python C:\Users\phate\MalTester.py

'''

malware_folder = "E:\\Malwares\\"
work_folder = "C:\\Users\\phate\\Desktop\\MalwareTests\\"
pin_executable = "C:\\pin\\pin.exe "
pin_tool ="C:\\pin\\FindOEPPin.dll"
pin_results = "C:\\pin\\PinUnpackerResults\\"
test_results = "E:\\Results\\"

def getCurrentMalware():
  #get the list of malwares to analize
  malwares = [f for f in listdir(malware_folder) if isfile(join(malware_folder, f))]
  if len(malwares) == 0:
    print("Malware folder empty")
    return None
  print("Current malwares "+str(malwares))
  #move the malware to the work folder
  from_path = join(malware_folder,malwares[0])  
  to_path = join(work_folder,malwares[0])
  print("Moving malware " + from_path +" to " +to_path)
  rename(from_path,to_path)
  return to_path

def runWithTimeout(cmd,timeout):
  proc = subprocess.Popen(cmd, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  poll_seconds = .250
  deadline = time.time()+timeout
  while time.time() < deadline and proc.poll() == None:
    time.sleep(poll_seconds)

  if proc.poll() == None:
    if float(sys.version[:3]) >= 2.6:
      proc.terminate()
  stdout, stderr = proc.communicate()
  return stdout, stderr, proc.returncode

def executePin(cur_malware):
  command = "%s -t %s -- %s "%(pin_executable,pin_tool, cur_malware)
  print("launching " + command)
  stdout,stderr,code =runWithTimeout(command,60)
  print("stdout: "+ stdout)
  print("stderror: "+stderr)


def moveResults(cur_malware):
  result = [f for f in listdir(pin_results) if isdir(join(pin_results, f))]
  if len(result) == None:
    print("No result folder created")
  pin_res_dir = join(pin_results,result[0])
  cur_mal_folder = cur_malware.split(".")[0]
  print("malware folder "+ cur_mal_folder)
  test_res_dir = join(test_results,cur_mal_folder)
  print("Moving result directory from %s to %s "%(pin_res_dir,test_res_dir))
  shutil.move(pin_res_dir,test_res_dir)

def main():
  cur_malware = getCurrentMalware()
  if cur_malware != None:  
    executePin(cur_malware)
    malware_name = cur_malware.split("\\")[-1]
    moveResults(malware_name)

main()


  
