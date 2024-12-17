import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk

class DuplicateFileChecker:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("중복 사진 및 동영상 파일 탐색기")
        self.root.geometry("600x400")
        
        self.folder_path = tk.StringVar()
        self.duplicates = []  # 중복 파일 목록

        self.create_ui()

    def create_ui(self):
        # 폴더 선택 UI
        tk.Label(self.root, text="대상 폴더:").pack(pady=5)
        tk.Entry(self.root, textvariable=self.folder_path, width=50).pack(pady=5)
        tk.Button(self.root, text="폴더 선택", command=self.choose_folder).pack(pady=5)
        tk.Button(self.root, text="중복 파일 검사", command=self.find_duplicates).pack(pady=5)
        
        # 결과 표시
        self.result_frame = tk.Frame(self.root)
        self.result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(self.result_frame, columns=("File", "Size"), show="headings")
        self.tree.heading("File", text="파일 경로")
        self.tree.heading("Size", text="파일 크기 (KB)")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # 삭제 버튼
        tk.Button(self.root, text="선택된 파일 삭제", command=self.delete_files).pack(pady=10)

    def choose_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
    
    def hash_file(self, file_path):
        """파일의 해시를 계산합니다."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return None
        return hash_md5.hexdigest()

    def find_duplicates(self):
        """폴더 안의 중복 파일을 탐색합니다."""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("경고", "대상 폴더를 선택해 주세요!")
            return
        
        file_hashes = {}
        self.duplicates.clear()

        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                if file.lower().endswith(('.jpg', '.jpeg', '.png', '.mp4', '.avi', '.mov')):
                    file_hash = self.hash_file(file_path)
                    if file_hash:
                        if file_hash in file_hashes:
                            self.duplicates.append((file_path, os.path.getsize(file_path) // 1024))
                        else:
                            file_hashes[file_hash] = file_path

        self.display_results()

    def display_results(self):
        """중복 파일을 Treeview에 표시합니다."""
        for i in self.tree.get_children():
            self.tree.delete(i)

        if not self.duplicates:
            messagebox.showinfo("완료", "중복된 파일이 없습니다!")
            return
        
        for file_path, size in self.duplicates:
            self.tree.insert("", "end", values=(file_path, size))

        messagebox.showinfo("완료", f"총 {len(self.duplicates)}개의 중복 파일을 찾았습니다!")

    def delete_files(self):
        """선택된 파일을 삭제합니다."""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("경고", "삭제할 파일을 선택해 주세요!")
            return
        
        confirm = messagebox.askyesno("확인", "선택된 파일을 삭제하시겠습니까?")
        if confirm:
            for item in selected_items:
                file_path = self.tree.item(item, "values")[0]
                try:
                    os.remove(file_path)
                    self.tree.delete(item)
                except Exception as e:
                    print(f"Error deleting file {file_path}: {e}")
            messagebox.showinfo("성공", "선택된 파일을 삭제했습니다.")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DuplicateFileChecker()
    app.run()
