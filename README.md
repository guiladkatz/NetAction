# NetAction
NetAction project code

Ben-Gurion University of the Negev

Faculty of Engineering Science

School of Electrical and Computer Engineering

Communication Systems Engineering

Fourth Year Engineering Project

### Final Project: **Caching-Based Acceleration Mechanisms in Datacenter Networks**

### Student: Guilad Katz

Advisors: Prof Chen Avin, Dr Gabriel Scalosub

### Steps for recreating the experiments:

In order to recreate the experiemnts performed in this project, follow the instructions below.

## Option 1 - Stateless BMv2
  There is a built image containing all the necessary software and including the stateless version of the BMv2 switch, Mininet and P4Runtime installed, including all their dependencies.
  1. Download the VM from [here] (https://drive.google.com/file/d/13NHWkkmn69W90dJGQUC7m7i4USeMTegF/view).
  2. Clone [this] (https://github.com/kevinbird61/p4-researching) repository into the VM.
  3. Go to p4-researching/src/fundamental and clone the this repository to that location.
  4. Move the "utils" folder form this repository to /p4-researching (Replacing the existing "utils" folder)
  5. Open a command line and navigate to p4-researching/src/fundamental/NetAction
  6. Be aware, that there might be some missing Python libraries. Please stay tuned to the errors regarding missing libraries, and install them if necessary.
  7. run ./sim_runner.sh (you'll might need to give it executable permissions)
  8. When the Mininet CLI opens, run "source xterms.sh" and three xterm windows will be opened
  9. in the window belonging to s1, run "./start_switch_cpu.sh"
  10. in the window belonging to h5, run "./start_p4_controller.sh"
  11. in the window belonging to h1, run "./tg.py"
  12. Now the simulation is running. Wait for h5 to print a "Finished" message, to indicate the end of the experiment.
  13. 5 new files were now created in the NetAction folder.
  14. This files are .txt files holding data gathered at the experiment:

      - Controller-Switch link utilization
      - Traffic arrival rate
      - Number of rule insertions to the cache
      - Number of evictions from the cache
      - Experiement parameters
  15. Use this data as desired. You may write a Python program to plot graphs. 



the VXLAN related P4 code is based on the code from: https://github.com/P4-Research/p4-demos/tree/master/vxlan

The controller is written in Python and is partially based on the code from: https://github.com/kevinbird61/p4-researching
