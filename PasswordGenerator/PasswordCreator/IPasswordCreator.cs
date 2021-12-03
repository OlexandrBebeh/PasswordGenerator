using System.Collections.Generic;

namespace PasswordGenerator.PasswordCreator
{
    public interface IPasswordCreator
    {
        public List<string> GeneratePasswords(int amount);
    }
}