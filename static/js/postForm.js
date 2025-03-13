document.addEventListener("DOMContentLoaded", function () {
  const priceInput = document.getElementById("price");
  const freeCheck = document.getElementById("free-check");
  const description = document.getElementById("description");
  const charCount = document.getElementById("charCount");
  const imageInput = document.getElementById("image");
  const previewImage = document.getElementById("image-preview");

  // 무료나눔 체크박스
  freeCheck.addEventListener("change", function () {
    if (this.checked) {
      priceInput.value = "";
      priceInput.disabled = true;
    } else {
      priceInput.disabled = false;
    }
  });

  // 글자 수 카운트
  description.addEventListener("input", function () {
    charCount.textContent = description.value.length;
  });

  // 이미지 미리보기
  imageInput.addEventListener("change", function () {
    const file = this.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = function (e) {
        previewImage.src = e.target.result;
        previewImage.style.display = "block";
      };
      reader.readAsDataURL(file);
    } else {
      previewImage.src = "#";
      previewImage.style.display = "none";
    }
  });
});

$("#post-form").on("submit", async function (e) {
  e.preventDefault();

  const title = $("#title").val().trim();
  const category = $("input[name='category']:checked").val();
  const price = $("#price").val().trim();
  const description = $("#description").val().trim();
  const isFree = $("#free-check").is(":checked");

  if (!title) return alert("제목을 입력해주세요.");
  if (!category) return alert("카테고리를 선택해주세요.");
  if (!isFree && (!price || isNaN(price))) return alert("가격을 입력해주세요.");
  if (!description) return alert("설명을 입력해주세요.");

  const form = $("#post-form")[0];
  const formData = new FormData(form);

  try {
    const res = await axios.post(`${baseURL}api/posts`, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
      withCredentials: true,
    });

    alert("게시물이 성공적으로 등록되었어요!");
    window.location.href = "/list";
  } catch (err) {
    console.error("❌ 게시글 등록 실패:", err);
    alert("게시글 등록 중 오류가 발생했어요 🥲");
  }
});
