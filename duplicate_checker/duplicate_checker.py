import os
import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from PIL import Image, ImageTk

class DuplicateFileChecker:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("중복 사진 및 동영상 파일 탐색기")
        self.root.geometry("1200x700")
        self.root.configure(bg="#f0f0f0")

        self.folder_path = tk.StringVar()
        self.duplicates = []  # 중복 파일 목록
        self.file_hashes = {}  # 해시별 원본 파일
        self.total_files = 0
        self.processed_files = 0
        self.is_running = False

        self.create_ui()

    def create_ui(self):
        # 좌우 이분할 프레임
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 좌측 프레임 (기능 및 리스트)
        left_frame = tk.LabelFrame(main_frame, text="파일 탐색 및 결과", font=("Arial", 12, "bold"), bg="#ffffff", relief=tk.GROOVE)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 상단 UI
        top_frame = tk.Frame(left_frame, bg="#ffffff")
        top_frame.pack(pady=10)
        
        tk.Label(top_frame, text="대상 폴더:", bg="#ffffff", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Entry(top_frame, textvariable=self.folder_path, width=50, font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="폴더 선택", command=self.choose_folder).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="중복 파일 검사", command=self.start_duplicate_check).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="중단", command=self.stop_checking).pack(side=tk.LEFT, padx=5)

        # 진행 상황 표시
        progress_frame = tk.Frame(left_frame, bg="#ffffff")
        progress_frame.pack(pady=10)
        
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", length=500, mode="determinate")
        self.progress.pack()
        self.progress_label = tk.Label(progress_frame, text="진행률: 0%", bg="#ffffff", font=("Arial", 10))
        self.progress_label.pack(pady=5)
        
        # 결과 표시 (Treeview)
        self.tree = ttk.Treeview(left_frame, columns=("Select1", "Original", "Select2", "Duplicate"), show="headings")
        self.tree.heading("Select1", text="선택", anchor="center")
        self.tree.heading("Original", text="원본 파일")
        self.tree.heading("Select2", text="선택", anchor="center")
        self.tree.heading("Duplicate", text="중복 파일")
        
        # 체크박스 열의 폭을 '선택' 텍스트 크기에 맞게 설정
        self.tree.heading("Select1", text="선택")
        font = tkfont.nametofont("TkHeadingFont")
        width = font.measure("선택") + 20  # 여백을 위해 20 픽셀 추가
        self.tree.column("Select1", width=width, anchor="center", stretch=False)
        self.tree.column("Select2", width=width, anchor="center", stretch=False)
        self.tree.column("Original", width=400)
        self.tree.column("Duplicate", width=400)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 전체 선택 및 삭제 버튼
        button_frame = tk.Frame(left_frame, bg="#ffffff")
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="전체 선택", command=self.select_all).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="전체 해제", command=self.deselect_all).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="선택된 파일 삭제", command=self.delete_selected_files).pack(side=tk.LEFT, padx=5)

        # 이벤트 바인딩
        self.tree.bind("<ButtonRelease-1>", self.handle_click)
        self.tree.bind("<ButtonRelease-1>", self.show_preview, add="+")

        # 우측 프레임 (미리보기)
        right_frame = tk.LabelFrame(main_frame, text="파일 미리보기", font=("Arial", 12, "bold"), bg="#ffffff", relief=tk.GROOVE)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.image_label1 = tk.Label(right_frame, bg="#ffffff")
        self.image_label1.pack(pady=5)
        self.image_label2 = tk.Label(right_frame, bg="#ffffff")
        self.image_label2.pack(pady=5)
        self.text_label = tk.Label(right_frame, text="", bg="#ffffff", font=("Arial", 10))
        self.text_label.pack()

    def handle_click(self, event):
        """클릭 이벤트를 처리하여 체크박스 상태를 토글합니다."""
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column = self.tree.identify_column(event.x)
            if column in ("#1", "#3"):  # Select1 또는 Select2 열을 클릭한 경우
                item = self.tree.identify_row(event.y)
                if item:
                    current_values = self.tree.item(item, "values")
                    if column == "#1":  # Select1 (원본 파일)
                        new_state = "☑" if current_values[0] == "☐" else "☐"
                        self.tree.item(item, values=(new_state, current_values[1], current_values[2], current_values[3]))
                    else:  # Select2 (중복 파일)
                        new_state = "☑" if current_values[2] == "☐" else "☐"
                        self.tree.item(item, values=(current_values[0], current_values[1], new_state, current_values[3]))

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

    def start_duplicate_check(self):
        """중복 파일 검사를 시작합니다."""
        threading.Thread(target=self.find_duplicates).start()

    def find_duplicates(self):
        """중복 파일을 탐색합니다."""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showwarning("경고", "대상 폴더를 선택해 주세요!")
            return

        self.duplicates.clear()
        self.file_hashes.clear()
        self.total_files = 0
        self.processed_files = 0
        self.is_running = True

        # 모든 파일 탐색
        files = []
        for root, _, filenames in os.walk(folder):
            for file in filenames:
                files.append(os.path.join(root, file))

        self.total_files = len(files)

        for file_path in files:
            if not self.is_running:
                break

            if not file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.mp4', '.avi', '.mov')):
                continue
            
            file_hash = self.hash_file(file_path)
            if file_hash:
                if file_hash in self.file_hashes:
                    self.duplicates.append((self.file_hashes[file_hash], file_path))
                else:
                    self.file_hashes[file_hash] = file_path

            self.processed_files += 1
            self.update_progress()

        self.display_results()
        self.is_running = False

    def stop_checking(self):
        """중복 파일 탐색 중단."""
        self.is_running = False

    def update_progress(self):
        """진행률 업데이트"""
        progress_percent = (self.processed_files / self.total_files) * 100
        self.progress["value"] = progress_percent
        self.progress_label.config(text=f"진행률: {int(progress_percent)}%")
        self.root.update_idletasks()

    def display_results(self):
        """중복 파일을 Treeview에 표시합니다."""
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        for original, duplicate in self.duplicates:
            self.tree.insert("", "end", values=("☐", original, "☐", duplicate))

    def select_all(self):
        """모든 파일을 선택합니다."""
        for item in self.tree.get_children():
            self.tree.item(item, values=("☑", self.tree.item(item, "values")[1], 
                                       "☑", self.tree.item(item, "values")[3]))

    def deselect_all(self):
        """모든 파일 선택을 해제합니다."""
        for item in self.tree.get_children():
            self.tree.item(item, values=("☐", self.tree.item(item, "values")[1], 
                                       "☐", self.tree.item(item, "values")[3]))

    def delete_selected_files(self):
        """선택된 파일을 삭제합니다."""
        files_to_delete = []
        items_to_remove = []
        
        # 삭제할 파일과 항목 수집
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            if values[0] == "☑":  # 원본 파일이 선택된 경우
                files_to_delete.append(values[1])
                items_to_remove.append(item)
            if values[2] == "☑":  # 중복 파일이 선택된 경우
                files_to_delete.append(values[3])
                items_to_remove.append(item)
        
        if not files_to_delete:
            messagebox.showwarning("경고", "삭제할 파일을 선택해 주세요!")
            return
        
        # 삭제 확인
        confirm = messagebox.askyesno("확인", f"선택된 {len(files_to_delete)}개의 파일을 삭제하시겠습니까?")
        if confirm:
            deleted_count = 0
            for file_path in files_to_delete:
                try:
                    os.remove(file_path)
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting file {file_path}: {e}")
            
            # 트리뷰에서 항목 제거
            for item in set(items_to_remove):  # 중복 제거를 위해 set 사용
                self.tree.delete(item)
            
            messagebox.showinfo("성공", f"{deleted_count}개의 파일이 삭제되었습니다.")

    def show_preview(self, event):
        """선택된 파일의 미리보기를 표시합니다."""
        selected_item = self.tree.selection()
        if not selected_item:
            return

        item_values = self.tree.item(selected_item[0], "values")
        if not item_values:
            return

        original, duplicate = item_values[1], item_values[3]

        if original.lower().endswith(('.jpg', '.jpeg', '.png')):
            image1 = Image.open(original)
            image1.thumbnail((200, 200))
            img1 = ImageTk.PhotoImage(image1)
            self.image_label1.config(image=img1)
            self.image_label1.image = img1

            image2 = Image.open(duplicate)
            image2.thumbnail((200, 200))
            img2 = ImageTk.PhotoImage(image2)
            self.image_label2.config(image=img2)
            self.image_label2.image = img2
            
            self.text_label.config(text="")
        else:
            self.image_label1.config(image="")
            self.image_label2.config(image="")
            self.text_label.config(text="동영상 파일입니다.")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DuplicateFileChecker()
    app.run()