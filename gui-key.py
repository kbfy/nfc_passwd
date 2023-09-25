import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

#全部通过AI编程

def xor_encrypt_decrypt(data, key):
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    return encrypted_data

def select_file():
    file_path = filedialog.askopenfilename()  # 使用文件对话框选择文件路径
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, file_path)

def show_message_box(message):
    messagebox.showinfo("结果", message)

def text_to_hex():
    file_path = file_path_entry.get()
    key = key_entry.get()

    if not file_path:
        show_message_box("未选择文件！")
        return

    with open(file_path, 'r') as file:
        text = file.read()
        text_with_blank = "blank" + text  # 在明文前添加预设文本
        hex_text = text_with_blank.encode().hex()
        encrypted_hex_text = xor_encrypt_decrypt(bytearray.fromhex(hex_text), key.encode())
        encrypted_hex_text = encrypted_hex_text.hex()

    new_file_path = os.path.splitext(file_path)[0] + "_hex.txt"

    with open(new_file_path, 'w') as file:
        file.write(encrypted_hex_text)

    message = "文本已转换为加密的十六进制并保存成功！保存路径为: " + new_file_path
    show_message_box(message)

def hex_to_text():
    file_path = file_path_entry.get()
    key = key_entry.get()

    if not file_path:
        show_message_box("未选择文件！")
        return

    with open(file_path, 'r') as file:
        encrypted_hex_text = file.read()
        encrypted_hex_data = bytearray.fromhex(encrypted_hex_text)
        decrypted_hex_data = xor_encrypt_decrypt(encrypted_hex_data, key.encode())
        decrypted_text = decrypted_hex_data.decode()

    # 检查解密后的文本是否包含预设文本
    if "blank" in decrypted_text:
        decrypted_text = decrypted_text.replace("blank", "")  # 移除预设文本

        message = "密码正确！"
        show_message_box(message)

        new_file_path = os.path.splitext(file_path)[0] + "_text.txt"

        with open(new_file_path, 'w') as file:
            file.write(decrypted_text)

        message = "加密的十六进制已转换为文本并保存成功！保存路径为: " + new_file_path
        show_message_box(message)
    else:
        message = "密码错误或加密数据已损坏。"
        show_message_box(message)

# 创建主窗口
window = tk.Tk()
window.title("空白NFC加密工具")
window.geometry("300x200")  # 设置窗口大小为400x200

# 创建标签和输入框
file_path_label = tk.Label(window, text="文件路径:")
file_path_label.pack()

file_path_entry = tk.Entry(window)
file_path_entry.pack()

file_select_button = tk.Button(window, text="选择文件", command=select_file)
file_select_button.pack()

key_label = tk.Label(window, text="密钥:")
key_label.pack()
key_entry = tk.Entry(window)
key_entry.pack()

# 创建按钮
text_to_hex_button = tk.Button(window, text="文本转换为加密的十六进制", command=text_to_hex)
text_to_hex_button.pack()

hex_to_text_button = tk.Button(window, text="加密的十六进制转换为文本", command=hex_to_text)
hex_to_text_button.pack()

# 运行主循环
window.mainloop()
