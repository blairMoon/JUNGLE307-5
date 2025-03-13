const categoryMap = {
  all: "전체",
  give: "나눔해요",
  need: "필요해요",
};

// $(document).ready(function () {
//   $(".category-link").on("click", function (e) {
//     e.preventDefault();

//     const categoryKey = $(this).data("category");
//     const categoryValue = categoryMap[categoryKey] || "전체";
//     const page = 1;
//     const accessToken = localStorage.getItem("accessToken");

//     axios
//       .get(`${baseURL}api/posts`, {
//         params: {
//           category: categoryValue,
//           page: page,
//         },
//         headers: {
//           "Content-Type": "multipart/form-data",
//           Authorization: `Bearer ${accessToken}`,
//         },
//       })
//       .then((res) => {
//         console.log("✅ 성공! 데이터:", res.data);
//       })
//       .catch((err) => {
//         console.error("❌ 오류 발생:", err);
//       });
//   });
// });
