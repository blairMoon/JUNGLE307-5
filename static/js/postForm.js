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

$(document).ready(function () {
  const form = $("#post-form")[0];
  const mode = form.dataset.mode;
  const postId = form.dataset.postId;
  const url =
    mode === "edit" ? `${baseURL}api/posts/${postId}` : `${baseURL}api/posts`;
  const method = mode === "edit" ? "patch" : "post";

  $("#post-form").on("submit", async function (e) {
    e.preventDefault();

    const title = $("#title").val().trim();
    const category = $("input[name='category']:checked").val();
    const price = $("#free").is(":checked") ? 0 : $("#price").val();
    const description = $("#description").val().trim();

    if (!title || !category || !description) {
      alert("제목, 카테고리, 설명은 필수입니다!");
      return;
    }

    const formData = new FormData(form);

    try {
      const res = await axios({
        method: method,
        url: url,
        data: formData,
        headers: {
          "Content-Type": "multipart/form-data",
        },
        withCredentials: true,
      });

      alert(res.data.message || "성공적으로 처리되었습니다!");
      location.href = "/list";
    } catch (err) {
      console.error("❌ 요청 실패:", err);
      alert(err.response?.data?.message || "요청 중 오류 발생!");
    }
  });
});
