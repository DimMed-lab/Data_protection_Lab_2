using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

class RSA
{
    static Random random = new Random();

    static void Main()
    {
        Console.WriteLine("Выберите битность RSA ключа:");
        Console.WriteLine("1. 1024");
        Console.WriteLine("2. 2048");
        Console.WriteLine("3. 4096");
        Console.WriteLine("4. 8192");
        Console.WriteLine("5. 16384");
        Console.WriteLine("6. 32768");

        int choice = int.Parse(Console.ReadLine());

        int keySize = 0;

        switch (choice)
        {
            case 1:
                keySize = 1024;
                break;
            case 2:
                keySize = 2048;
                break;
            case 3:
                keySize = 4096;
                break;
            case 4:
                keySize = 8192;
                break;
            case 5:
                keySize = 16384;
                break;
            case 6:
                keySize = 32768;
                break;
            default:
                Console.WriteLine("Неверный выбор. Программа завершена.");
                return;
        }

        Tuple<BigInteger, BigInteger> publicKey;
        Tuple<BigInteger, BigInteger> privateKey;

        Console.WriteLine(DateTime.Now.ToString());
        GenerateKeysParallel(keySize, out publicKey, out privateKey);

        Console.WriteLine($"\nОткрытый ключ (Exponent): 0x{publicKey.Item1.ToString("X")}");
        Console.WriteLine($"Открытый ключ (Modulus): 0x{publicKey.Item2.ToString("X")}");

        Console.WriteLine($"\nЗакрытый ключ (D): 0x{privateKey.Item1.ToString("X")}");
        Console.WriteLine($"Закрытый ключ (Modulus): 0x{privateKey.Item2.ToString("X")}");

        Console.WriteLine(DateTime.Now.ToString());

        Console.Write("\nВведите сообщение для шифрования: ");
        string message = Console.ReadLine();

        // Шифрование
        BigInteger encryptedMessage = Encrypt(message, publicKey);
        Console.WriteLine("\nЗашифрованное сообщение: 0x" + encryptedMessage.ToString("X"));

        // Расшифрование (для проверки)
        string decryptedMessage = Decrypt(encryptedMessage, privateKey);
        Console.WriteLine("Расшифрованное сообщение: " + decryptedMessage);
    }

    static void GenerateKeysParallel(int keySize, out Tuple<BigInteger, BigInteger> publicKey, out Tuple<BigInteger, BigInteger> privateKey)
    {
        List<BigInteger> primes = GeneratePrimesParallel(keySize);

        BigInteger p = primes[0];
        BigInteger q = primes[1];

        BigInteger n = BigInteger.Multiply(p, q);
        BigInteger phi = BigInteger.Multiply(p - 1, q - 1);

        BigInteger e = ChooseExponent(phi);
        BigInteger d = ModInverse(e, phi);

        publicKey = Tuple.Create(e, n);
        privateKey = Tuple.Create(d, n);
    }

    static List<BigInteger> GeneratePrimesParallel(int bits)
    {
        List<BigInteger> primes = new List<BigInteger>();

        Parallel.ForEach(Enumerable.Range(0, 2), i =>
        {
            do
            {
                byte[] data = new byte[bits / 8];
                random.NextBytes(data);
                BigInteger prime = BigInteger.Abs(new BigInteger(data));

                if (IsProbablePrime(prime, 5))
                {
                    lock (primes)
                    {
                        primes.Add(prime);
                    }
                }
            } while (primes.Count < 2);
        });

        return primes;
    }

    static bool IsProbablePrime(BigInteger n, int k)
    {
        if (n < 2)
            return false;
        if (n < 4)
            return true;
        if (n % 2 == 0)
            return false;

        BigInteger d = n - 1;
        int s = 0;

        while (d % 2 == 0)
        {
            d >>= 1; // Эквивалент d /= 2, но более эффективный способ для BigInteger
            s++;
        }

        for (int i = 0; i < k; i++)
        {
            BigInteger a = RandomBigInteger(2, n - 2); // Генерация случайного числа в интервале (2, n - 2)
            BigInteger x = BigInteger.ModPow(a, d, n);

            if (x == 1 || x == n - 1)
                continue;

            bool isWitness = false;

            for (int r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, n);

                if (x == 1)
                    return false;

                if (x == n - 1)
                {
                    isWitness = true;
                    break;
                }
            }

            if (!isWitness)
                return false;
        }

        return true;
    }

    static BigInteger RandomBigInteger(BigInteger min, BigInteger max)
    {
        byte[] bytes = max.ToByteArray();
        BigInteger result;

        do
        {
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= (byte)0x7F; // Убираем знак
            result = new BigInteger(bytes);
        } while (result < min || result >= max);

        return result;
    }

    static BigInteger ChooseExponent(BigInteger phi)
    {
        BigInteger e;
        do
        {
            e = new BigInteger(random.Next(2, (int)phi.ToByteArray()[0]));
        }
        while (BigInteger.GreatestCommonDivisor(e, phi) != 1);

        return e;
    }

    static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m;
        BigInteger x0 = 0;
        BigInteger x1 = 1;

        if (m == 1)
            return 0;

        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;

            m = a % m;
            a = t;
            t = x0;

            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return x1;
    }

    static BigInteger Encrypt(string message, Tuple<BigInteger, BigInteger> publicKey)
    {
        BigInteger e = publicKey.Item1;
        BigInteger n = publicKey.Item2;

        byte[] bytes = Encoding.UTF8.GetBytes(message);
        BigInteger m = new BigInteger(bytes);

        return BigInteger.ModPow(m, e, n);
    }

    static string Decrypt(BigInteger encryptedMessage, Tuple<BigInteger, BigInteger> privateKey)
    {
        BigInteger d = privateKey.Item1;
        BigInteger n = privateKey.Item2;

        BigInteger decryptedMessage = BigInteger.ModPow(encryptedMessage, d, n);
        byte[] bytes = decryptedMessage.ToByteArray();
        return Encoding.UTF8.GetString(bytes);
    }
}