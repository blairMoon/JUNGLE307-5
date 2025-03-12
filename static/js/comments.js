$(document).ready(function () {
  // 게시글 ID 가져오기 (예: <section class="comments" data-post-id="{{ post.id }}">)
  const postId = $(".comments").data("post-id");

  $(".comment-form").on("submit", async function (e) {
    e.preventDefault(); // 기본 제출 막기

    const content = $(this).find("textarea").val().trim();

    if (!content) {
      alert("댓글을 입력해주세요!");
      return;
    }

    try {
      const response = await axios.post(
        `http://127.0.0.1:5001/api/posts/${postId}/comments`,
        { content },
        {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true, // ✅ 쿠키 기반 인증 시 꼭 필요!
        }
      );

      alert("댓글이 등록되었습니다!");
      location.reload(); // 또는 댓글 동적으로 추가해도 돼!
    } catch (error) {
      console.error("❌ 댓글 등록 실패:", error);
      alert(error?.response?.data?.message || "댓글 등록 중 오류 발생!");
    }
  });

  // 대댓글 토글
  $(".toggle-reply").on("click", function () {
    $(this).siblings(".reply-form").toggleClass("hidden");
  });
});
$(document).ready(function () {
  const postId = $(".comments").data("post-id");

  // ✅ 답글 입력 폼 제출 이벤트
  $(".reply-form").on("submit", async function (e) {
    e.preventDefault();

    const commentId = $(this).data("comment-id"); // 대댓글을 달 대상 댓글 ID
    const content = $(this).find(".reply-input").val().trim();

    if (!content) {
      alert("답글을 입력해주세요!");
      return;
    }

    try {
      const res = await axios.post(
        `http://127.0.0.1:5001/api/posts/${postId}/comments/${commentId}/replies`,
        { content },
        {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true, // ✅ 쿠키 전송
        }
      );

      alert("답글이 등록되었습니다!");
      location.reload(); // 등록 후 새로고침 or 동적 렌더링도 가능
    } catch (err) {
      console.error("❌ 대댓글 등록 실패:", err);
      alert(err?.response?.data?.message || "대댓글 등록 중 오류 발생!");
    }
  });

  // ✅ 답글 토글 버튼
  $(".toggle-reply").on("click", function () {
    const replyForm = $(this).siblings(".reply-form");
    replyForm.toggleClass("hidden");
  });
});
