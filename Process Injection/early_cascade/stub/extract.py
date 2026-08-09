import pefile
import argparse


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description = "Extracts shellcode from a PE file.")
        parser.add_argument("-f", required = True, help = 'Path to the source executabele', type = str);
        parser.add_argument("-o", required = True, help = 'Path to the output raw binary', type = str);
        option = parser.parse_args()

        PeExe = pefile.PE( option.f );
        PeSec = PeExe.sections[0].get_data();

        if PeSec.find(b'ENDOFCODE') != None:
            ScRaw = PeSec[ : PeSec.find(b'ENDOFCODE') ];
            f = open(option.o, 'wb');
            f.write(ScRaw);
            f.close();
        else:
            print("[!] Error: no ending tag.");
    except Exception as e:
        print(f"[!] Error: {e}");