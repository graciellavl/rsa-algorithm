from pydoc import plain
import PySimpleGUI as sg
from pathlib import Path
import sys

from algorsa import rsa_decrypt, rsa_encrypt, generatekey

sg.theme('DarkAmber')

layout1 = [[sg.Text("File", font=('Arial', 14, 'bold'))],
           [
    sg.Text("Input File Name"),
    sg.Input(key='inputFile'),
    sg.FileBrowse(file_types=(("TXT Files", "*.txt"), ("ALL Files", "*.*"))),
]]
layout2 = [[sg.Text("Plain", font=('Arial', 14, 'bold'))],
           [sg.Text("Input"), sg.Input(key="inputPlain")],
           [sg.Text("Output"), sg.Input(key="output")]]

layout = [[sg.Text("Welcome to RSA Algorithm Cipher", font=('Arial', 16, 'bold'))],
          [sg.Text('_' * 80)],
          [sg.Text("Pilih opsi masukan", font=('Arial', 14))],
          [sg.Button('File'), sg.Button('Plain')],
          [sg.Text('_' * 80)],
          [sg.Text("Pilih action", font=('Arial', 14))],
          [sg.Radio("Encrypt", "Action", default=True, key="encrypt"), sg.Radio(
              "Decrypt", "Action", default=False, key="decrypt")],
          [
    sg.Text("Kunci Publik"),
    sg.Input(key='public_key_file'),
    sg.FileBrowse(file_types=(("TXT Files", "*.txt"), ("ALL Files", "*.*"))),
    sg.Text("atau ketik manual: "),
    sg.Input(key="manual_public_key")
],
    [
    sg.Text("Kunci Private"),
    sg.Input(key='private_key_file'),
    sg.FileBrowse(file_types=(("TXT Files", "*.txt"), ("ALL Files", "*.*"))),
        sg.Text("atau ketik manual: "),
    sg.Input(key="manual_private_key")
],
    [sg.Text('_' * 80)],
    [sg.Column(layout1, key='fileLayout'),
     sg.Column(layout2, visible=False, key='plainLayout')], [sg.Button('Execute'), sg.Button('RESET')],
    [sg.Text("Nama File Output:"), sg.Input(key="outputFilename")],
    [sg.Button('Save input to file', key="saveInput"),
     sg.Button('Save output to file', key="saveOutput")],
    [sg.Text('_' * 80)],
    [sg.Text("Lama waktu enkripsi/dekripsi: "), sg.Text(key="time")],
    [sg.Text("Ukuran file hasil enkripsi/dekripsi: "), sg.Text(key="size")]
]

window = sg.Window('RSA Algorithm Cipher', layout)

layout = "fileLayout"
plaintext = ""
ciphertext = ""
time = 0
size = 0
while True:
    # Display and interact with the Window
    event, values = window.read()

    if event == "File":
        window[layout].update(visible=False)
        layout = "fileLayout"
        window[layout].update(visible=True)

    elif event == "Plain":
        window[layout].update(visible=False)
        layout = "plainLayout"
        window[layout].update(visible=True)

    if event == "Execute":
        if layout == "fileLayout":
            if values["encrypt"]:
                if (values["manual_public_key"] or values["public_key_file"]):
                    if (values["manual_public_key"]):
                        public = values["manual_public_key"]
                        public_key = bytes(
                            public.split()[0], 'utf-8'), bytes(public.split()[1], 'utf-8')
                        public_key = int.from_bytes(
                            public_key[0], "big"), int.from_bytes(public_key[1], "big")
                    else:
                        filename = values["public_key_file"]
                        if Path(filename).is_file():
                            try:
                                with open(filename, "rb") as f:
                                    public = f.read()
                                    public_key = int.from_bytes(public.split()[0], byteorder='big'), int.from_bytes(
                                        public.split()[1], byteorder='big')
                            except Exception as e:
                                print("Error: ", e)
                else:
                    public_key, private_key = generatekey()

                if Path(values["inputFile"]).is_file():
                    try:
                        with open(values["inputFile"], "rb") as f:
                            plaintext = f.read()
                    except Exception as e:
                        print("Error: ", e)
                int_val = int.from_bytes(plaintext, "big")

                ciphertext, time = rsa_encrypt(str(int_val), public_key)
                with open(f'output/{values["inputFile"].split(".")[0]}-enc.{values["inputFile"].split(".")[1]}', "wb") as f:
                    f.write(bytes(ciphertext, 'latin-1'))
                window.Element(key="time").Update(f'{time} seconds')
                window.Element(key="size").Update(
                    f'{sys.getsizeof(ciphertext)} bytes')

            elif values["decrypt"]:
                if (values["manual_private_key"] or values["private_key_file"]):
                    ciphertext = ""
                    if Path(values["inputFile"]).is_file():
                        try:
                            with open(values["inputFile"], "rb") as f:
                                ciphertext = f.read()
                        except Exception as e:
                            print("Error: ", e)
                    if (values["manual_private_key"]):
                        private = values["manual_private_key"]
                        private_key = bytes(
                            private.split()[0], 'utf-8'), bytes(private.split()[1], 'utf-8')
                        private_key_int = int.from_bytes(
                            private_key[0], "big"), int.from_bytes(private_key[1], "big")
                        int_val_plaintext, time = rsa_decrypt(
                            ciphertext, private_key_int)
                        int_val_plaintext = int(str_val_plaintext)
                        bytes_val = int_val_plaintext.to_bytes(5, 'big')
                        plaintext = bytes_val.decode('utf-8')
                    else:
                        filename = values["private_key_file"]
                        if Path(filename).is_file():
                            try:
                                with open(filename, "rb") as f:
                                    private = f.read()
                                    private_key = int.from_bytes(private.split()[0], byteorder='big'), int.from_bytes(
                                        private.split()[1], byteorder='big')
                                    str_val_plaintext, time = rsa_decrypt(
                                        ciphertext, private_key)
                                    int_val_plaintext = int(str_val_plaintext)
                                    bytes_val = int_val_plaintext.to_bytes(
                                        5, 'big')
                                    plaintext = bytes_val.decode('utf-8')
                            except Exception as e:
                                print("Error: ", e)
                    window.Element(key="output").Update(plaintext)
                    window.Element(key="time").Update(f'{time} seconds')
                    window.Element(key="size").Update(
                        f'{sys.getsizeof(plaintext)} bytes')
                else:
                    sg.Popup("Masukkan private key!")

# Plain

        elif layout == "plainLayout":
            if values["encrypt"]:
                if (values["manual_public_key"] or values["public_key_file"]):
                    if (values["manual_public_key"]):
                        public = values["manual_public_key"]
                        public_key = bytes(
                            public.split()[0], 'utf-8'), bytes(public.split()[1], 'utf-8')
                        public_key = int.from_bytes(
                            public_key[0], "big"), int.from_bytes(public_key[1], "big")
                    else:
                        filename = values["public_key_file"]
                        if Path(filename).is_file():
                            try:
                                with open(filename, "rb") as f:
                                    public = f.read()
                                    public_key = int.from_bytes(public.split()[0], byteorder='big'), int.from_bytes(
                                        public.split()[1], byteorder='big')
                            except Exception as e:
                                print("Error: ", e)
                else:
                    public_key, private_key = generatekey()

                byte_val = bytes(values["inputPlain"], 'utf=8')
                int_val = int.from_bytes(byte_val, "big")

                ciphertext, time = rsa_encrypt(str(int_val), public_key)
                window.Element(key="output").Update(hex(int(ciphertext)))
                window.Element(key="time").Update(f'{time} seconds')
                window.Element(key="size").Update(
                    f'{sys.getsizeof(ciphertext)} bytes')

            elif values["decrypt"]:
                if (values["manual_private_key"] or values["private_key_file"]):
                    if (values["manual_private_key"]):
                        private = values["manual_private_key"]
                        private_key = bytes(
                            private.split()[0], 'utf-8'), bytes(private.split()[1], 'utf-8')
                        private_key_int = int.from_bytes(
                            private_key[0], "big"), int.from_bytes(private_key[1], "big")
                        int_val_plaintext, time = rsa_decrypt(
                            values["inputPlain"], private_key_int)
                        int_val_plaintext = int(str_val_plaintext)
                        bytes_val = int_val_plaintext.to_bytes(5, 'big')
                        plaintext = bytes_val.decode('utf-8')
                    else:
                        filename = values["private_key_file"]
                        if Path(filename).is_file():
                            try:
                                with open(filename, "rb") as f:
                                    private = f.read()
                                    private_key = int.from_bytes(private.split()[0], byteorder='big'), int.from_bytes(
                                        private.split()[1], byteorder='big')
                                    str_val_plaintext, time = rsa_decrypt(
                                        values["inputPlain"], private_key)
                                    int_val_plaintext = int(str_val_plaintext)
                                    bytes_val = int_val_plaintext.to_bytes(
                                        5, 'big')
                                    plaintext = bytes_val.decode('utf-8')
                            except Exception as e:
                                print("Error: ", e)
                    window.Element(key="output").Update(plaintext)
                    window.Element(key="time").Update(f'{time} seconds')
                    window.Element(key="size").Update(
                        f'{sys.getsizeof(plaintext)} bytes')
                else:
                    sg.Popup("Masukkan private key!")

    if event == "saveInput":
        if (values["outputFilename"] == ""):
            continue
        else:
            with open("output/" + values["outputFilename"], 'wb') as f:
                if layout == "plainLayout":
                    f.write(bytes(values["inputPlain"], "utf-8"))
                else:
                    continue

    if event == "saveOutput":
        if (values["outputFilename"] == ""):
            continue
        else:
            with open("output/" + values["outputFilename"], 'wb') as f:
                if layout == "plainLayout":
                    f.write(bytes(values["output"], "utf-8"))
                else:
                    continue

    if event == "RESET":
        window.Element(key="inputFile").Update("")
        window.Element(key="inputPlain").Update("")
        window.Element(key="output").Update("")
        window.Element(key="manual_public_key").Update("")
        window.Element(key="manual_private_key").Update("")
        window.Element(key="public_key_file").Update("")
        window.Element(key="private_key_file").Update("")
        window.Element(key="outputFilename").Update("")
        window.Element(key="time").Update("")
        window.Element(key="size").Update("")
    if event == sg.WIN_CLOSED:
        break

# Finish up by removing from the screen
window.close()                                  # Part 5 - Close the Window
