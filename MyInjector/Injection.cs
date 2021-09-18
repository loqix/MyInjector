using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyInjector.Injection
{
    public class InjectionDetail
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string[] Candidates { get; set; }
    }

    public class InjectionMethodDescriptor
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public InjectionDetail[] Details { get; set; }
    }

    public static class InjectionMethodManager
    {
        public static InjectionMethodDescriptor[] GetInjectionMethods()
        {
            List<InjectionMethodDescriptor> ret = new List<InjectionMethodDescriptor>();

            // 'IM' is short for 'Injection Method'
            // "DE" stands for "Injection Detail"
            InjectionDetail DE_ProcessAccess = new InjectionDetail
            {
                Name = "ProcessAccess",
                Description = "Method by which we access a process.",
                Candidates = new string[] { "Open Process", "Steal Token", "Kernel" }
            };
            InjectionDetail DE_EntryPoint = new InjectionDetail
            {
                Name = "EntryPoint",
                Description = "Code entry point in host process.",
                Candidates = new string[] { "LoadLibrary", "LdrLoadDll", "Manual Load" }
            };
            InjectionDetail DE_GainExecution = new InjectionDetail
            {
                Name = "GainExecution",
                Description = "Method by which we transfer control flow to our code.",
                Candidates = new string[] { "CreateRemoteThread", "QueueUserAPC", "InstrumentCallback" }
            };

            var IM_Common = new InjectionMethodDescriptor()
            {
                Name = "Common",
                Description = "Injection by execute code in host context and load target dll.",
                Details = new InjectionDetail[] { DE_ProcessAccess, DE_EntryPoint, DE_GainExecution }
            };
            ret.Add(IM_Common);

            var IM_SetWindowHook = new InjectionMethodDescriptor()
            {
                Name = "SetWindowHook",
                Description = "Injection using API SetWindowHook().",
                Details = null
            };
            ret.Add(IM_SetWindowHook);

            var IM_IME = new InjectionMethodDescriptor()
            {
                Name = "Windows IME",
                Description = "Injection using Windows Input Method Editor",
                Details = null
            };
            ret.Add(IM_IME);

            return ret.ToArray();
        }

        public static bool PerformInjection(InjectionMethodDescriptor method, string[] details)
        {
            return false;
        }
    }
}
