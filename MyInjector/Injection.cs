using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyInjector.Injection
{
    public class InjectionNode
    {
        public string Name { get; set; }
        public CandidateMethod[] Candidates { get; set; }
        public int DefaultCandidate { get; set; } = 0;
    }

    public class CandidateMethod
    { 
        public string Name { get; set; }
        public string Description { get; set; }
    }

    public class MajorMethod : CandidateMethod
    {
        public InjectionNode[] MinorNodes { get; set; }
    }

    public class MajorNode : InjectionNode
    { 
        public MajorMethod[] MajorCandidates
        {
            get
            {
                return Candidates as MajorMethod[];
            }
        }
    }

    public static class InjectionMethodManager
    {
        public static MajorNode MajorNode
        {
            get
            {
                if (_majorNode is null)
                {
                    InitNodes();
                }
                return _majorNode;
            }
        }

        public static void InitNodes()
        {
            CandidateMethod ProcessAccess_OpenProcess = new CandidateMethod
            {
                Name = "OpenProcess",
                Description = "Get process handle by OpenProcess()."
            };
            CandidateMethod ProcessAccess_StealToken = new CandidateMethod
            {
                Name = "Duplicate Handle",
                Description = "Get process handle by duplicate a handle from another process."
            };
            CandidateMethod ProcessAccess_Kernel = new CandidateMethod
            {
                Name = "Kernel",
                Description = "Access to target process by the assistance from kernel module."
            };
            InjectionNode Node_ProcessAccess = new InjectionNode
            {
                Name = "Process Access",
                Candidates = new CandidateMethod[] { ProcessAccess_OpenProcess, ProcessAccess_StealToken, ProcessAccess_Kernel }
            };

            CandidateMethod EntryPoint_LoadLibrary = new CandidateMethod
            {
                Name = "LoadLibrary",
                Description = "Entry point: LoadLibrary()."
            };
            CandidateMethod EntryPoint_LdrLoadDll = new CandidateMethod
            {
                Name = "LdrLoadDll",
                Description = "Entry point: LdrLoadDll()."
            };
            CandidateMethod EntryPoint_ManualLoad = new CandidateMethod
            {
                Name = "Manual Load",
                Description = "Entry point: a shell code that load the target dll manually."
            };
            InjectionNode Node_EntryPoint = new InjectionNode
            {
                Name = "Entry Point",
                Candidates = new CandidateMethod[] { EntryPoint_LoadLibrary, EntryPoint_LdrLoadDll, EntryPoint_ManualLoad }
            };

            CandidateMethod GainExecution_RemoteThread = new CandidateMethod
            {
                Name = "CreateRemoteThread",
                Description = "Gain execution using API CreateRemoteThread()."
            };
            CandidateMethod GainExecution_APC = new CandidateMethod
            {
                Name = "QueueUserAPC",
                Description = "Gain execution using API QueueUserAPC()."
            };
            CandidateMethod GainExecution_InstrumentCallback = new CandidateMethod
            {
                Name = "InstrumentCallback",
                Description = "Gain execution by windows's InstrumentCallback."
            };
            InjectionNode Node_GainExecution = new InjectionNode
            {
                Name = "Gain Execution",
                Candidates = new CandidateMethod[] { GainExecution_RemoteThread, GainExecution_APC, GainExecution_InstrumentCallback }
            };

            MajorMethod Major_Common = new MajorMethod
            {
                Name = "Common",
                Description = "Execute a piece of code in target process's context and load our image.",
                MinorNodes = new InjectionNode[] { Node_ProcessAccess, Node_EntryPoint, Node_GainExecution }
            };
            MajorMethod Major_SetWindowHook = new MajorMethod
            {
                Name = "SetWindowHook",
                Description = "Injection using API SetWindowHook().",
                MinorNodes = null
            };
            MajorMethod Major_IME = new MajorMethod
            {
                Name = "IME",
                Description = "Injection using Windows Input Method Editor(IME)."
            };
            _majorNode = new MajorNode
            {
                Name = "Injection Method",
                Candidates = new CandidateMethod[] { Major_Common, Major_SetWindowHook, Major_IME }
            };
        }

        public static bool PerformInjection(MajorMethod method, string[] details)
        {
            return false;
        }

        private static MajorNode _majorNode = null;
    }
}
