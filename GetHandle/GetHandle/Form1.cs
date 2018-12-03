using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace GetHandle
{
    public partial class Form1 : Form
    {
        IntPtr procHandle;
        string cmdArg0 = "\"C:\\Users\\quinn\\Desktop\\Forensic Tools\\Detection\\YARA\\yara64.exe\" "; //path to yara exe
        string cmdArg1 = "\"C:\\Users\\quinn\\Desktop\\Forensic Tools\\Detection\\YARA\\Rules.txt\" "; //path to Rules
        string cmdArg2 = "{%}procID{%}"; //%ProcId%
        string x;
        int cmdflag = 0;
       
        public Form1()
        {
            var PID = new List<int>();
            var ProcList = new List<string>();
        
            Process[] procs = Process.GetProcesses(); //Returns an array of all open processes into procs
            IntPtr hWnd;
            foreach (Process proc in procs)
            {
                if ((hWnd = proc.MainWindowHandle) != IntPtr.Zero)
                {
                    Console.WriteLine("{0} : {1}", proc.ProcessName, hWnd);
                    Console.WriteLine("PID of {0} : {1}", proc.ProcessName, proc.Id);
                    PID.Add(proc.Id); //Save list of PID's into a int list named PID
                    ProcList.Add(proc.ProcessName); //Save list of PID's into string list 
                    if (proc.ProcessName == "cmd")
                    {
                        procHandle = hWnd; //Injection handle
                    }
                 
                }
            }

            Console.WriteLine("Process Handle2 = {0}", procHandle);
            if (ProcList.Contains("cmd") == false){

                MyProc openProc = new MyProc();
                openProc.OpenApplication("C:\\Windows\\System32\\cmd.exe");
                cmdflag = 1;
                foreach (Process proc in procs)
                {
                    if ((hWnd = proc.MainWindowHandle) != IntPtr.Zero || cmdflag == 1)
                    {
                        Console.WriteLine("{0} : {1}", proc.ProcessName, hWnd);
                        Console.WriteLine("PID of {0} : {1}", proc.ProcessName, proc.Id);
                        PID.Add(proc.Id); //Save list of PID's into a int list named PID
                        ProcList.Add(proc.ProcessName); //Save list of PID's into string list 
                        if (proc.ProcessName == "cmd")
                        {
                            procHandle = hWnd; //Injection handle
                        }
                        cmdflag = 0;
                    }
                }

                //Console.WriteLine("{0} : {1}", Process.ProcessName, procHandle);


            }

            foreach (int item in PID) //For each PID in the PID list, 
            {
                var v1 = extfunc.SetForegroundWindow(procHandle);
                var v2 = extfunc.GetLastError();
                
                SendKeys.SendWait("SET /A procID=" + item);
                SendKeys.SendWait("{ENTER}");
                SendKeys.SendWait(cmdArg0 + cmdArg1 + cmdArg2);
                SendKeys.SendWait("{ENTER}");
                Console.WriteLine("SetForeGroundWindow: {0}", v1);
                Console.WriteLine("Last error code: {0}", v2);
               // Console.ReadLine();

            }
          
              
           
            

            InitializeComponent();


        }

    
    }
}

public class extfunc
{
    public delegate bool EnumDelegate(IntPtr hwnd, int lParam); //Filter

    //User32 Imports
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint = "GetWindowText", //Grab Window Text
        ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int GetWindowText(IntPtr hwnd, StringBuilder lpWindowText, int nMaxCount);
    [DllImport("user32.dll", EntryPoint = "EnumDesktopWindows", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool EnumDesktopWindows(IntPtr hdesktop, EnumDelegate lpEnumCallbackFunction, IntPtr lparam);
    [DllImport("user32.dll", EntryPoint = "GetForegroundWindow", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", EntryPoint = "SetForegroundWindow", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    //kernel32 imports
    [DllImport("kernel32.dll", EntryPoint = "GetLastError", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint GetLastError();

    [DllImport("kernel32.dll", EntryPoint = "GetProcessId", ExactSpelling = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int GetProcessId(IntPtr handle);

    


}
class MyProc
{
     public void OpenApplication(string ApplicationPath)
    {
        Process.Start(ApplicationPath);
    }

}