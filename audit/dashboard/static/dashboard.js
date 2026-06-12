(function () {
  function parseValue(value, type) {
    if (type === "number") {
      const parsed = Number.parseFloat(value);
      return Number.isNaN(parsed) ? 0 : parsed;
    }

    return String(value || "").toLowerCase();
  }

  function getRowValue(row, key, type) {
    return parseValue(row.dataset[key], type);
  }

  function clearIndicators(table) {
    table.querySelectorAll(".sort-button").forEach((button) => {
      button.classList.remove("sort-asc", "sort-desc");
      const indicator = button.querySelector(".sort-indicator");
      if (indicator) {
        indicator.textContent = "";
      }
    });
  }

  function setIndicator(button, direction) {
    button.classList.add(direction === "asc" ? "sort-asc" : "sort-desc");
    const indicator = button.querySelector(".sort-indicator");
    if (indicator) {
      indicator.textContent = direction === "asc" ? "▲" : "▼";
    }
  }

  function sortTable(table, button, forceDirection) {
    const key = button.dataset.sortKey;
    const type = button.dataset.sortType || "text";
    const tbody = table.querySelector("tbody");

    if (!key || !tbody) {
      return;
    }

    const currentKey = table.dataset.sortKey;
    const currentDirection = table.dataset.sortDirection || "asc";

    let direction = forceDirection;
    if (!direction) {
      if (currentKey === key && currentDirection === "asc") {
        direction = "desc";
      } else {
        direction = "asc";
      }
    }

    const rows = Array.from(tbody.querySelectorAll("tr"));

    rows.sort((a, b) => {
      const aValue = getRowValue(a, key, type);
      const bValue = getRowValue(b, key, type);

      if (aValue < bValue) {
        return direction === "asc" ? -1 : 1;
      }
      if (aValue > bValue) {
        return direction === "asc" ? 1 : -1;
      }

      const aStageOrder = getRowValue(a, "stageOrder", "number");
      const bStageOrder = getRowValue(b, "stageOrder", "number");
      return aStageOrder - bStageOrder;
    });

    rows.forEach((row) => tbody.appendChild(row));

    table.dataset.sortKey = key;
    table.dataset.sortDirection = direction;

    clearIndicators(table);
    setIndicator(button, direction);
  }

  function initializeSortableTables() {
  document.querySelectorAll(".sortable-table").forEach((table) => {
    const buttons = table.querySelectorAll(".sort-button");

    buttons.forEach((button) => {
      button.addEventListener("click", () => sortTable(table, button));
    });
  });
}

  document.addEventListener("DOMContentLoaded", initializeSortableTables);
})();