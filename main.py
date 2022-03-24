from pydoc import plain
import PySimpleGUI as sg
from pathlib import Path

from algorsa import rsa_decrypt, rsa_encrypt

sg.theme('DarkAmber')

layout1 = [[sg.Text("File", font=('Arial', 14, 'bold'))],
           [
    sg.Text("Input File Name"),
    sg.Input(key='inputFile'),
    sg.FileBrowse(file_types=(("TXT Files", "*.txt"), ("ALL Files", "*.*"))),
], ]
layout2 = [[sg.Text("Plain", font=('Arial', 14, 'bold'))],
           [sg.Text("Input"), sg.Input(key="inputPlain")],
           [sg.Text("Output"), sg.Input(key="output")],
           [sg.Button('Execute'), sg.Button('RESET')]]

layout = [[sg.Text("Welcome to RSA Algorithm Cipher", font=('Arial', 16, 'bold'))],
          [sg.Text('_' * 80)],
          [sg.Text("Pilih opsi masukan", font=('Arial', 14))],
          [sg.Button('File'), sg.Button('Plain')],
          [sg.Text('_' * 80)],
          [sg.Text("Pilih action", font=('Arial', 14))],
          [sg.Radio("Encrypt", "Action", default=True, key="encrypt"), sg.Radio(
              "Decrypt", "Action", default=False, key="decrypt")],
          [sg.Text('_' * 80)],
          [sg.Column(layout1, key='fileLayout'),
           sg.Column(layout2, visible=False, key='plainLayout')],
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
            window.Element(key="outputfile") # TODO
        elif layout == "plainLayout":
            if values["encrypt"]:
                ciphertext = rsa_encrypt(values["inputPlain"])
                window.Element(key="output").Update(ciphertext)
            elif values["decrypt"]:
                plaintext = rsa_decrypt(values["inputPlain"])
                window.Element(key="output").Update(plaintext)

    if event == "saveInput":
        if (values["outputFilename"] == ""):
            continue
        else:
            with open(values["outputFilename"], 'wb') as f:
                if layout == "plainLayout":
                    f.write(bytes(values["inputPlain"], "utf-8"))
                    size = "10"
                    window.Element(key="size").Update(f'{size} bytes')
                else:
                    continue
                    # f.write(bytes("decrypt"), "utf-8")              # TODO

    if event == "saveOutput":
        if (values["outputFilename"] == ""):
            continue
        else:
            with open(values["outputFilename"], 'wb') as f:
                if layout == "plainLayout":
                    f.write(bytes(values["output"], "utf-8"))
                    size = "10"
                    window.Element(key="size").Update(f'{size} bytes')
                else:
                    continue
                    # f.write(bytes("decrypt"), "utf-8")              # TODO

    if event == sg.WIN_CLOSED:
        break
# Finish up by removing from the screen
window.close()                                  # Part 5 - Close the Window
