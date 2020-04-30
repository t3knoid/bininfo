using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace bininfo
{
    /// <summary>
    /// A simple command-line parser
    /// </summary>
    public class CommandLine
    {
        public CommandLine()
        {
            Arguments = new Dictionary<string, string[]>();
        }
        public IDictionary<string, string[]> Arguments { get; private set; }
        public void Parse(string[] args)
        {
            var currentName = "";
            var values = new List<string>();
            foreach (var arg in args)
            {
                if (arg.StartsWith("-"))
                {
                    if (currentName != "")
                        Arguments[currentName] = values.ToArray();

                    values.Clear();
                    currentName = arg.Substring(1);
                }
                else if (currentName == "")
                    Arguments[arg] = new string[0];
                else
                    values.Add(arg);
            }

            if (currentName != "")
                Arguments[currentName] = values.ToArray();
        }
        public bool Contains(string name)
        {
            return Arguments.ContainsKey(name);
        }
    }
}
